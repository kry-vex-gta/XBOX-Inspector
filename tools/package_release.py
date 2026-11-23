"""Pack only distributable Inspector files. Never traverses the input build."""
import hashlib
import argparse
import os
from pathlib import Path
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def descendants(path):
    return (p for p in path.rglob("*")
            if p.is_file() and not p.is_symlink() and "__pycache__" not in p.parts)


def pack(directory, package, members):
    directory.mkdir(exist_ok=True)
    target = directory / f"{package}.zip"
    with zipfile.ZipFile(target, "x") as archive:
        hashes = []
        for member, source in sorted(members.items()):
            content = source.read_bytes()
            info = zipfile.ZipInfo(f"{package}/{member}", FIXED_TIME)
            archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            hashes.append(f"{hashlib.sha256(content).hexdigest()}  {member}\n")
        archive.writestr(zipfile.ZipInfo(f"{package}/SHA256SUMS", FIXED_TIME), "".join(hashes))
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
    with target.open("rb") as stream:
        print(f"{hashlib.file_digest(stream, 'sha256').hexdigest()}  {target}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    target_root = ROOT / os.environ.get("CARGO_TARGET_DIR", "target")
    docs = ["README.md", "LICENSE", "ATTRIBUTION.md", "VERIFICATION.md"]
    documents = {name: ROOT / name for name in docs}
    documents.update({p.relative_to(ROOT).as_posix(): p for p in descendants(ROOT / "docs")})
    indexes = {p.relative_to(ROOT).as_posix(): p for p in (ROOT / "indexes").glob("*.json")}
    binary = {
        **documents, **indexes,
        "bin/XBOX-Inspector.exe": target_root / "release/XBOX-Inspector.exe",
        "Start-XBOX-Inspector.cmd": ROOT / "packaging/Start-XBOX-Inspector.cmd",
        "tools/ghidra_metadata.py": ROOT / "tools/ghidra_metadata.py",
        "tools/ghidra/ExportPeMetadata.java": ROOT / "tools/ghidra/ExportPeMetadata.java",
        "tools/verify_open_indexes.py": ROOT / "tools/verify_open_indexes.py",
        **{f"licenses/{p.name}": p for p in (ROOT / "assets/fonts").glob("OFL-*.txt")},
    }
    source = {
        **documents, **indexes,
        **{name: ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")},
    }
    for directory in ("crates", "packaging", "tools", "assets"):
        source.update({p.relative_to(ROOT).as_posix(): p for p in descendants(ROOT / directory)})
    for name, files in (("win64", binary), ("source", source)):
        if (args.output / f"XBOX-Inspector-{VERSION}-{name}.zip").exists():
            raise FileExistsError("release ZIP already exists; select a fresh source checkout or archive it")
        if not all(p.is_file() for p in files.values()):
            raise FileNotFoundError("a required distribution file is missing")
    pack(args.output, f"XBOX-Inspector-{VERSION}-win64", binary)
    pack(args.output, f"XBOX-Inspector-{VERSION}-source", source)
