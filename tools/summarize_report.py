"""Summarize a smoke report: key numbers vs the expected snapshot."""
import json, pathlib, sys

p = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else r"work\smoke-report.json")
r = json.loads(p.read_text(encoding="utf-8"))
print("schema:", r["schema"], "| tool:", r["tool"], r["tool_version"])
print("files:", r["file_count"], "| logical_bytes:", r["logical_bytes"])
print("rpf9:", len(r["rpf9"]), "| rds5:", len(r["rds5"]))
desc = sum(s.get("etpf_descriptors") or 0 for s in r["rds5"])
avail = sum(s["counts"].get("AVAILABLE", 0) for s in r["rds5"])
ver = sum(s["counts"].get("SUCCESS_VERIFIED", 0) for s in r["rds5"])
print("rds5 descriptors:", desc, "| blocks AVAILABLE:", avail, "| SUCCESS_VERIFIED:", ver)
rds5_err = [s["rel"] for s in r["rds5"] if s.get("metadata_error")]
print("rds5 metadata errors:", rds5_err[:5], "count:", len(rds5_err))
pf = r["runtime_preflight"]
print("preflight exe:", pf["declared_executable"], "| found:", pf["executable_found"], "| ready:", pf["launch_ready"])
for b in pf["blockers"]:
    print("  blocker:", b)
for iv in r["index_verifications"]:
    print("index:", iv["source_path"], f'{iv["entries_verified"]}/{iv["entries_total"]}', "coverage:", iv["coverage_bytes"])
for v in r["video_verifications"]:
    print("video:", v["rel"], f'{v["records_verified"]}/{v["records_total"]}', "bytes:", v["verified_record_bytes"], "failed:", len(v["failed"]))
for c in r["coverage"]:
    print(f'coverage: {c["archive"]} {c["union_verified_bytes"]}/{c["archive_bytes"]} = {c["percent"]:.3f}%')
t = r["resource_totals"]
print("totals:", json.dumps(t, ensure_ascii=False))
tests = r["tests"]
print("selftests:", sum(1 for x in tests if x["passed"]), "/", len(tests))
for n in r["notes"]:
    print("note:", n)
kinds = {}
for f in r["files"]:
    kinds[f["file_type"]] = kinds.get(f["file_type"], 0) + 1
print("kinds:", json.dumps(kinds, ensure_ascii=False))
