"""Independent Python zlib check of declared open ranges, with no resource export."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import zlib


def verify(root, index_path):
    if index_path.stat().st_size > 64 << 20:
        raise ValueError("index size exceeds the report budget")
    data = json.loads(index_path.read_text(encoding="utf-8"))
    if data.get("schema") != "xbox-inspector-range-index/1":
        raise ValueError("unknown index schema")
    root = root.resolve(strict=True)
    source = (root / data["source_path"]).resolve(strict=True)
    if not source.is_relative_to(root) or not source.is_file():
        raise ValueError("index source is outside the selected root or is not a file")
    with source.open("rb") as stream:
        initial = os.fstat(stream.fileno())
        if initial.st_size != data["source_size"]:
            raise ValueError("index and file size differ")
        wanted_source_hash = data.get("source_sha256")
        if wanted_source_hash is not None:
            if hashlib.file_digest(stream, "sha256").hexdigest() != wanted_source_hash.lower():
                raise ValueError("source hash differs")
        stored = decoded = 0
        hashes = hashlib.sha256()
        for row in data["entries"]:
            start, count, size = row["offset"], row["stored_len"], row["expected_len"]
            if (row["encoding"] != "zlib" or not 0 < count <= 64 << 20 or not 0 <= size <= 64 << 20
                    or start < 0 or start + count > initial.st_size):
                raise ValueError(f"invalid open range {row['id']}")
            stream.seek(start)
            compressed = stream.read(count)
            if len(compressed) != count:
                raise ValueError(f"short source read for {row['id']}")
            inflater = zlib.decompressobj()
            payload = inflater.decompress(compressed, size + 1)
            digest = hashlib.sha256(payload).hexdigest()
            if (len(payload) != size or not inflater.eof or inflater.unused_data
                    or inflater.unconsumed_tail or digest != row["sha256"].lower()):
                raise ValueError(f"independent verification failed for {row['id']}")
            hashes.update(bytes.fromhex(digest))
            stored += count
            decoded += size
        last = os.fstat(stream.fileno())
        if (initial.st_size, initial.st_mtime_ns) != (last.st_size, last.st_mtime_ns):
            raise ValueError("source changed during verification")
    return {"source": data["source_path"], "verified": len(data["entries"]),
            "stored_range_sum_bytes": stored, "decoded_bytes": decoded,
            "ordered_output_hashes_sha256": hashes.hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("indexes", nargs="+", type=Path)
    args = parser.parse_args()
    rows = [verify(args.root, index) for index in args.indexes]
    print(json.dumps({"zlib": zlib.ZLIB_RUNTIME_VERSION, "total_verified": sum(r["verified"] for r in rows),
                      "archives": rows}, indent=2))
