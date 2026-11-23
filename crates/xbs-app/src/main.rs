mod cli;
mod gui;
mod i18n;
mod pipeline;
mod report_mcp;
mod selftest;
mod settings;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        None => gui::run(None),
        Some("gui") => gui::run(args.get(1).cloned()),
        Some("scan") => cli::scan(&args[1..]),
        Some("selftest") => cli::selftest(),
        Some("mcp-reports") if args.len() == 2 => {
            match report_mcp::run(std::path::Path::new(&args[1])) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("MCP: {e}");
                    1
                }
            }
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_usage();
            0
        }
        Some(other) => {
            eprintln!("Неизвестная команда: {other}\n");
            print_usage();
            2
        }
    };
    std::process::exit(code);
}

fn print_usage() {
    println!(
        "XBOX-Inspector {} — инвентаризация Xbox-сборки, проверка открытых диапазонов, preflight запуска\n\n\
         Команды:\n\
         \x20 (без аргументов) | gui [папка]   графический интерфейс\n\
         \x20 scan <папка> [опции]             проверка в терминале\n\
         \x20 selftest                         self-тесты метода (8 ZLIB + учёт диапазонов)\n\n\
         \x20 mcp-reports <папка отчётов>     MCP stdio только для чтения отчётов\n\n\
         Опции scan:\n\
         \x20 --json <путь>      сохранить отчёт JSON\n\
         \x20 --md <путь>        сохранить отчёт Markdown\n\
         \x20 --work <папка>     каталог артефактов (по умолчанию рядом с exe: .\\work)\n\
         \x20 --indexes <папка>  каталог встроенных индексов (по умолчанию .\\indexes рядом с exe)\n\
         \x20 --index <файл>     дополнительный индекс диапазонов (можно несколько)\n\
         \x20 --hash-all         полный SHA-256 каждого файла (долго: сотни ГБ)\n\
         \x20 --deep             глубокая проверка блоков RDS5 (распаковка ZLIB, долго)\n\
         \x20 --scan-open        поиск открытых ZLIB/Bink потоков в RPF9\n\n\
         Исходная папка открывается только на чтение. Артефакты пишутся в --work.",
        env!("CARGO_PKG_VERSION")
    );
}
