"""Optional Ghidra adapter. Inspect one authorized local PE without running it."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory, gettempdir


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def is_pe(path):
    with path.open("rb") as stream:
        prefix = stream.read(64)
        if len(prefix) != 64 or prefix[:2] != b"MZ":
            return False
        offset, = struct.unpack_from("<I", prefix, 60)
        if not 64 <= offset <= path.stat().st_size - 4:
            return False
        stream.seek(offset)
        return stream.read(4) == b"PE\0\0"


def inspect(ghidra, root, source, work):
    root = root.resolve(strict=True)
    source = source.resolve(strict=True)
    work = work.resolve(strict=True)
    if not source.is_relative_to(root) or work.is_relative_to(root):
        raise ValueError("select a PE within the input root and a separate output directory")
    if not source.is_file() or not (0 < source.stat().st_size <= 64 << 20) or not is_pe(source):
        raise ValueError("input must be a regular PE of at most 64 MiB")
    launcher = (ghidra / "support/analyzeHeadless.bat").resolve(strict=True)
    script_dir = Path(__file__).resolve().parent / "ghidra"
    # Ghidra does not accept a project directory under a dot-prefixed ancestor.
    scratch = Path(gettempdir()).resolve(strict=True) if any(part.startswith(".") for part in work.parts) else work
    if scratch.is_relative_to(root):
        raise ValueError("Ghidra scratch directory must be outside the input")
    with TemporaryDirectory(prefix="xbs-ghidra-", dir=scratch) as location:
        temp = Path(location)
        if not temp.resolve(strict=True).is_relative_to(scratch):
            raise ValueError("created Ghidra project path does not belong to the scratch folder")
        copy = temp / "sample.exe"
        local = temp / "result.json"
        project = temp / "projects"
        project.mkdir()
        with source.open("rb") as origin, copy.open("xb") as destination:
            shutil.copyfileobj(origin, destination)
        original_hash = sha256(copy)
        if original_hash != sha256(source):
            raise ValueError("the detached PE differs from the input")
        args = [
            str(launcher), str(project), "InspectorMetadata", "-import", str(copy),
            "-readOnly", "-noanalysis", "-scriptPath", str(script_dir),
            "-log", str(temp / "ghidra.log"), "-scriptlog", str(temp / "script.log"),
            "-postScript", "ExportPeMetadata.java", str(local),
        ]
        if any(c in arg for arg in args for c in '%!^&|<>"\r\n'):
            raise ValueError("unsupported character in headless launcher arguments")
        result = subprocess.run(args, cwd=temp, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=90, check=False)
        if result.returncode or not local.is_file() or local.stat().st_size > 128 << 10:
            raise RuntimeError(f"Ghidra metadata export failed (exit code {result.returncode})")
        report = json.loads(local.read_text(encoding="utf-8"))
        if (report.get("schema") != "xbox-inspector-ghidra-metadata/1"
                or report.get("guest_executed") is not False
                or report.get("ghidra_source_sha256", "").lower() != original_hash
                or sha256(source) != original_hash):
            raise ValueError("Ghidra result and verified input do not agree")
        report["source"] = source.name
        return report


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--ghidra-home", type=Path, required=True)
    cli.add_argument("--input-root", type=Path, required=True)
    cli.add_argument("--pe", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    parent = args.output.parent.resolve(strict=True)
    report = inspect(args.ghidra_home, args.input_root, args.pe, parent)
    with (parent / args.output.name).open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
        target.write("\n")
