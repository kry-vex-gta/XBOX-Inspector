"""Validate a fresh release and run the fixture-by-environment test matrix."""
import argparse
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import time
import zipfile
import zlib


def unpack(package, output):
    output.mkdir()
    with zipfile.ZipFile(package) as archive:
        members = archive.namelist()
        assert len({i.casefold() for i in members}) == len(members) and archive.testzip() is None
        assert len({PurePosixPath(i).parts[0] for i in members}) == 1
        assert all(not PurePosixPath(i).is_absolute() and ".." not in PurePosixPath(i).parts
                   and "\\" not in i and ":" not in i for i in members)
        archive.extractall(output)
    root, = output.iterdir()
    manifest = dict(line.split("  ", 1)[::-1] for line in (root / "SHA256SUMS").read_text().splitlines())
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*")
              if p.is_file() and p.name != "SHA256SUMS"}
    assert set(manifest) == actual
    for name, expected in manifest.items():
        assert sha256((root / name).read_bytes()).hexdigest() == expected, name
    assert not any(part in {"target", "base", "work"} for name in actual for part in PurePosixPath(name).parts)
    return root, len(manifest)


def entry(index, offset, payload, decoded=None):
    result = {
        "id": str(index), "offset": offset, "stored_len": len(payload),
        "sha256": sha256(decoded if decoded is not None else payload).hexdigest(),
        "encoding": "zlib" if decoded is not None else "raw", "kind": "owned-fixture",
    }
    if decoded is not None:
        result["expected_len"] = len(decoded)
    return result


def prepare(case, root, pe):
    root.mkdir(parents=True)
    a = b"owned evidence" * 23
    b = b"second test" * 31
    if case in (1, 2):
        za = zlib.compress(a)
        zb = zlib.compress(b)
        data = za if case == 1 else za + zb
        entries = [entry(0, 0, za, a)]
        if case == 2:
            entries.append(entry(1, len(za), zb, b))
    elif case == 5:
        data = a
        entries = [entry(0, 0, a), entry(1, len(a), b)]
    elif case == 6:
        data = b"0123456789abcdef"
        entries = [entry(0, 2, data[2:8]), entry(1, 4, data[4:12]), entry(2, 13, data[13:15])]
    elif case == 8:
        data = a
        entries = [entry(0, 0, a)]
    else:
        entries = []
        if case == 3:
            data = b""
        elif case == 4:
            data = b"opaque owned format"
        elif case == 7:
            data = a
            (root / "duplicate.bin").write_bytes(a)
        else:
            if case == 9:
                shutil.copyfile(pe, root / "owned.exe")
            (root / "MicrosoftGame.Config").write_text(
                '<Game><ExecutableList><Executable Name="owned.exe" TargetDeviceFamily="Scarlett"/>'
                '</ExecutableList></Game>', encoding="utf8")
            return None
    (root / "sample.bin").write_bytes(data)
    if not entries:
        return None
    index = {"schema": "xbox-inspector-range-index/1", "source_path": "sample.bin",
             "source_size": len(data), "entries": entries}
    if case == 8:
        index["source_sha256"] = sha256(b"z" * len(a)).hexdigest()
    return index


def expectation(case, report, oracle):
    totals = report["resource_totals"]
    if case in (1, 2):
        assert totals["additional_ranges_verified_hash"] == case
        assert totals["ranges_unconfirmed"] == 0
    elif case == 3:
        assert report["file_count"] == 1 and report["logical_bytes"] == 0
    elif case == 4:
        assert report["files"][0]["file_type"].lower() == "unknown"
    elif case == 5:
        statuses = [row["status"] for row in report["index_verifications"][0]["entries"]]
        assert statuses == ["VERIFIED_HASH", "TRUNCATED_FILE"], statuses
    elif case == 6:
        assert report["index_verifications"][0]["coverage_bytes"] == oracle
    elif case == 7:
        assert report["file_count"] == 2
        assert len({row["source_sha256"] for row in report["files"]}) == 1
    elif case == 8:
        assert report["index_verifications"][0]["entries"][0]["status"] == "IDENTITY_MISMATCH"
    elif case == 9:
        pre = report["runtime_preflight"]
        assert pre["executable_found"] and pre["pe_static"]["entry_in_executable_section"]
        assert pre["launch_ready"] is False
    elif case == 10:
        pre = report["runtime_preflight"]
        assert pre["declared_executable"] == "owned.exe" and not pre["executable_found"]


def executed(exe, *args, **kwargs):
    return subprocess.run([str(exe), *map(str, args)], capture_output=True, timeout=45, **kwargs)


def matrix(exe, qa, pe, oracle):
    checks = []
    for case in range(1, 11):
        reference = None
        fixture_main = qa / f"fixture-{case}"
        for context in range(1, 11):
            number = 100 + (case - 1) * 10 + context
            if context in (5, 7, 9):
                checks.append({"id": number, "status": "not_run", "reason":
                               "native GUI index parity not automated" if context != 9 else "parallel inner worker pool not implemented"})
                continue
            folder = fixture_main if context in (1, 2, 6, 8, 10) else qa / f"{'has a space' if context == 3 else 'проверка набора'} {case}"
            output = qa / f"result-{case}" if context in (1, 2) else qa / f"result-{case}-{context}"
            output.mkdir(exist_ok=True)
            index_path = qa / f"index-{case}-{context}.json"
            if folder.exists():
                index = json.loads((qa / f"index-{case}-1.json").read_text(encoding="utf8")) if (qa / f"index-{case}-1.json").is_file() else None
            else:
                index = prepare(case, folder, pe)
            cmd = ["scan", folder, "--indexes", qa / "empty-indexes", "--work", output,
                   "--lang", "en" if context == 6 else "ru"]
            if index is not None:
                index_path.write_text(json.dumps(index), encoding="utf8")
                cmd += ["--index", index_path]
            if case == 7 or context == 8:
                cmd += ["--hash-all"]
            start = time.monotonic()
            proc = executed(exe, *cmd)
            elapsed = time.monotonic() - start
            if proc.returncode:
                raise RuntimeError(f"case {number} failed: {proc.stderr[-1000:].decode('utf8', 'replace')}")
            report = json.loads((output / "report.json").read_text(encoding="utf8"))
            expectation(case, report, oracle)
            summary = report["resource_totals"]
            if reference is None:
                reference = summary
            assert reference == summary, (number, reference, summary)
            checks.append({"id": number, "status": "pass", "input": folder.name,
                           "command": [exe.name, *map(str, cmd)], "totals": summary,
                           "seconds": round(elapsed, 4),
                           "evidence": "fixture-specific expectation and invariant counters"})
    return checks


def mcp(exe, qa):
    root = qa / "mcp reports"
    root.mkdir()
    (root / "example.json").write_text('{"example":true}\n', encoding="utf8")
    calls = [
        (1, "initialize", {"protocolVersion": "2025-11-25"}),
        (2, "tools/list", {}),
        (3, "tools/call", {"name": "list_reports", "arguments": {}}),
        (4, "tools/call", {"name": "read_report", "arguments": {"name": "example.json"}}),
        (5, "tools/call", {"name": "read_report", "arguments": {"name": "missing.json"}}),
    ]
    request = "".join(json.dumps({"jsonrpc": "2.0", "id": i, "method": m, "params": p}) + "\n" for i, m, p in calls)
    result = executed(exe, "mcp-reports", root, input=request.encode("utf8"))
    assert result.returncode == 0, result.stderr
    responses = {v["id"]: v["result"] for v in map(json.loads, result.stdout.splitlines())}
    assert responses[1]["protocolVersion"] == "2025-11-25"
    assert len(responses[2]["tools"]) == 2
    assert json.loads(responses[3]["content"][0]["text"]) == ["example.json"]
    assert json.loads(responses[4]["content"][0]["text"])["text"] == '{"example":true}\n'
    assert responses[5]["isError"]
    return len(responses)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("qa", type=Path)
    parser.add_argument("owned_pe", type=Path)
    parser.add_argument("--union-reference", type=int, required=True)
    args = parser.parse_args()
    args.qa.mkdir()
    root, file_count = unpack(args.archive.resolve(strict=True), args.qa / "тест распаковки ZIP")
    exe = root / "bin/XBOX-Inspector.exe"
    selftest = executed(exe, "selftest")
    assert selftest.returncode == 0 and b"10/10" in selftest.stdout, selftest.stderr
    checks = matrix(exe, args.qa, args.owned_pe.resolve(strict=True), args.union_reference)
    summary = {"manifest_matched": file_count, "selftest_passed": 10,
               "mcp_protocol_checks": mcp(exe, args.qa),
               "matrix_passed": sum(row["status"] == "pass" for row in checks),
               "matrix_not_run": sum(row["status"] == "not_run" for row in checks), "matrix": checks}
    (args.qa / "release-qa.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf8")
    print(json.dumps({k: v for k, v in summary.items() if k != "matrix"}, ensure_ascii=False))
