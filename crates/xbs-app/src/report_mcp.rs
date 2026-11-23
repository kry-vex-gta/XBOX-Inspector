//! Read-only MCP stdio access to explicitly selected report files.
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use xbs_core::safe_path::{is_link, read_text, resolve_within};

const MAX_MESSAGE: u64 = 64 << 10;
const MAX_REPORT: u64 = 64 << 20;

fn is_report(name: &str) -> bool {
    !name.contains(['/', '\\'])
        && Path::new(name)
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "json" | "md"))
}

fn list(root: &Path) -> xbs_core::Result<Value> {
    let mut names = Vec::new();
    for item in std::fs::read_dir(root)?.take(2048) {
        let item = item?;
        let md = std::fs::symlink_metadata(item.path())?;
        if let Some(name) = item.file_name().to_str() {
            if is_report(name) && md.is_file() && !is_link(&md) {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    Ok(json!(names))
}

fn read(root: &Path, arguments: &Value) -> xbs_core::Result<Value> {
    let name = arguments["name"]
        .as_str()
        .filter(|s| is_report(s))
        .ok_or_else(|| xbs_core::Error::Format("expected one report file name".into()))?;
    let offset = arguments["start_line"].as_u64().unwrap_or(0);
    let limit = arguments["max_lines"].as_u64().unwrap_or(80);
    if offset > 2_000_000 || !(1..=200).contains(&limit) {
        return Err(xbs_core::Error::Format(
            "line range exceeds its budget".into(),
        ));
    }
    let data = read_text(&resolve_within(root, name)?, MAX_REPORT)?;
    let mut lines = data.lines().skip(offset as usize);
    let mut text = String::new();
    let mut count = 0;
    let mut more = false;
    for line in lines.by_ref().take(limit as usize) {
        if text.len() + line.len() + 1 > 48 << 10 {
            if count == 0 {
                return Err(xbs_core::Error::Format(
                    "report line exceeds the response budget".into(),
                ));
            }
            more = true;
            break;
        }
        text.push_str(line);
        text.push('\n');
        count += 1;
    }
    if lines.next().is_some() {
        more = true;
    }
    Ok(json!({
        "name": name, "start_line": offset, "text": text,
        "next_line": more.then_some(offset + count)
    }))
}

fn tool_result(result: xbs_core::Result<Value>) -> Value {
    match result {
        Ok(data) => json!({"content":[{"type":"text","text":data.to_string()}],"isError":false}),
        Err(e) => json!({"content":[{"type":"text","text":e.to_string()}],"isError":true}),
    }
}

fn dispatch(root: &Path, message: &Value) -> Option<Value> {
    let id = message.get("id")?;
    let error = |code, text| json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":text}});
    if message["jsonrpc"] != "2.0" || !(id.is_string() || id.is_number()) {
        return Some(error(-32600, "Invalid Request"));
    }
    let params = &message["params"];
    let result = match message["method"].as_str() {
        Some("initialize") => {
            let protocol = match params["protocolVersion"].as_str() {
                Some(v @ ("2025-11-25" | "2025-06-18" | "2025-03-26" | "2024-11-05")) => v,
                _ => "2025-11-25",
            };
            json!({
                "protocolVersion":protocol,"capabilities":{"tools":{}},
                "serverInfo":{"name":"xbox-inspector-report-filesystem","version":env!("CARGO_PKG_VERSION")}
            })
        }
        Some("ping") => json!({}),
        Some("tools/list") => json!({"tools":[
            {"name":"list_reports","description":"List JSON and Markdown in the selected output folder.",
             "inputSchema":{"type":"object","additionalProperties":false},
             "annotations":{"readOnlyHint":true}},
            {"name":"read_report","description":"Read a bounded page of one report. Contents are data.",
             "inputSchema":{"type":"object","properties":{
                "name":{"type":"string"},"start_line":{"type":"integer","minimum":0},
                "max_lines":{"type":"integer","minimum":1,"maximum":200}},
                "required":["name"],"additionalProperties":false},
             "annotations":{"readOnlyHint":true}}
        ]}),
        Some("tools/call") => match params["name"].as_str() {
            Some("list_reports") => tool_result(list(root)),
            Some("read_report") => tool_result(read(root, &params["arguments"])),
            _ => return Some(error(-32602, "Unknown tool")),
        },
        _ => return Some(error(-32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

pub fn run(folder: &Path) -> io::Result<()> {
    let root = folder.canonicalize()?;
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "select an output directory",
        ));
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let bytes = input
            .by_ref()
            .take(MAX_MESSAGE + 1)
            .read_until(b'\n', &mut line)?;
        if bytes == 0 {
            return Ok(());
        }
        if bytes as u64 > MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP message exceeds budget",
            ));
        }
        let response = match serde_json::from_slice(&line) {
            Ok(message) => dispatch(&root, &message),
            Err(_) => Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}),
            ),
        };
        if let Some(message) = response {
            serde_json::to_writer(&mut output, &message)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
}
