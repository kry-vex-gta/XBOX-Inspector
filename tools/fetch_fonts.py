"""Download redistributable fonts (OFL) for ru/kk/zh-Hans UI coverage."""
import urllib.request, pathlib

HERE = pathlib.Path(__file__).resolve().parent
FONTS = HERE.parent / "assets" / "fonts"
FONTS.mkdir(parents=True, exist_ok=True)

items = [
    ("NotoSans-Regular.ttf",
     "https://github.com/notofonts/noto-fonts/raw/main/hinted/ttf/NotoSans/NotoSans-Regular.ttf"),
    ("NotoSansSC-Regular.ttf",
     "https://github.com/google/fonts/raw/main/ofl/notosanssc/NotoSansSC%5Bwght%5D.ttf"),
    ("OFL-NotoSans.txt",
     "https://github.com/notofonts/noto-fonts/raw/main/LICENSE"),
    ("OFL-NotoSansSC.txt",
     "https://github.com/google/fonts/raw/main/ofl/notosanssc/OFL.txt"),
]
for name, url in items:
    dest = FONTS / name
    print("fetch", name)
    data = urllib.request.urlopen(url, timeout=300).read()
    dest.write_bytes(data)
    print("  bytes:", len(data))
print("done")
