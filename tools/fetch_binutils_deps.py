"""Fetch binutils runtime deps from MSYS2 into the same local prefix."""
import urllib.request, re, tarfile, pathlib, io

BASE = "https://repo.msys2.org/mingw/mingw64/"
html = urllib.request.urlopen(BASE, timeout=60).read().decode()
dest = pathlib.Path(r"C:\Users\1\tools\binutils")

for name in ["libiconv", "gettext-runtime", "libwinpthread", "zlib", "zstd"]:
    pat = rf'mingw-w64-x86_64-{name}-[0-9][^"]*-any\.pkg\.tar\.zst'
    pkgs = sorted(set(re.findall(pat, html)))
    # filter out -devel/-docs etc: keep plain runtime package
    pkgs = [p for p in pkgs if not re.search(r'-(devel|docs|debug|python|tools|static)', p)]
    url = BASE + pkgs[-1]
    print("fetch", pkgs[-1])
    data = urllib.request.urlopen(url, timeout=300).read()
    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:zst")
    tf.extractall(dest, filter="data")

print("dlls:", sorted(p.name for p in (dest / "mingw64" / "bin").glob("*.dll")))
