"""Convert SimuXBOX 0.1.0 verification outputs into XBOX-Inspector bundled indexes.
Read-only on the base reports; writes only into ../../indexes."""
import json, pathlib

HERE = pathlib.Path(__file__).resolve().parent
BASE = HERE.parent / "base"
OUT = HERE.parent / "indexes"
OUT.mkdir(exist_ok=True)

# 1. Claims (independent range catalog, 140 entries)
claims = json.loads((BASE / "recovery-tools" / "Claims.json").read_text(encoding="utf-8"))
out = {"schema": "xbox-inspector-claims/1",
       "provenance": "SimuXBOX 0.1.0 Unified_Recovery_Tools/Claims.json (snapshot-bound)",
       "claims": claims}
(OUT / "claims.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
print("claims:", len(claims))

# 2. Video index (515 Bink records)
vs = json.loads((BASE / "reports" / "VIDEO_FRESH_SCAN.json").read_text(encoding="utf-8"))
cur = vs["current"]
records = []
for v in cur["videos"]:
    records.append({
        "offset": v["offset"], "size": v["size"], "revision": v["revision"],
        "width": v["width"], "height": v["height"], "frames": v["frames"],
        "fps": v["fps"], "flags": v["flags"], "largest_frame": v["largest_frame"],
        "header_and_index_sha256": v["header_and_index_sha256"],
    })
out = {"schema": "xbox-inspector-video-index/1",
       "provenance": "SimuXBOX 0.1.0 Reports/VIDEO_FRESH_SCAN.json",
       "source_path": "movies.rpf",
       "source_size": vs["source_size"],
       "source_sha256": vs["source_sha256"],
       "records": records}
(OUT / "movies-video.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
print("video records:", len(records))

# 3. Source hashes (116 game files)
entries = []
for line in (BASE / "reports" / "Unified_Source_Verification.jsonl").read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    j = json.loads(line)
    entries.append({"path": j["path"], "size": j["bytes"], "sha256": j["sha256"]})
out = {"schema": "xbox-inspector-source-hashes/1",
       "provenance": "SimuXBOX 0.1.0 Reports/Unified_Source_Verification.jsonl",
       "entries": entries}
(OUT / "source-hashes.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
print("source hashes:", len(entries))
