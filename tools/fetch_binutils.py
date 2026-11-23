"""Fetch MSYS2 mingw-w64 binutils (as.exe, dlltool.exe, ld.exe) for the GNU Rust build."""
import urllib.request, re, tarfile, pathlib, io

html = urllib.request.urlopen("https://repo.msys2.org/mingw/mingw64/", timeout=60).read().decode()
pkgs = sorted(set(re.findall(r'mingw-w64-x86_64-binutils-[0-9][^"]*-any\.pkg\.tar\.zst', html)))
print("candidates:", pkgs[-3:])
url = "https://repo.msys2.org/mingw/mingw64/" + pkgs[-1]
print("downloading", url)
data = urllib.request.urlopen(url, timeout=300).read()
print("bytes:", len(data))
dest = pathlib.Path(r"C:\Users\1\tools\binutils")
dest.mkdir(parents=True, exist_ok=True)
tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:zst")
tf.extractall(dest, filter="data")
print("extracted to", dest)
print([p.name for p in (dest / "mingw64" / "bin").glob("*.exe")][:20])
