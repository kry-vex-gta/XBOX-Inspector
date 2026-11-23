"""Open hidden test windows from the Windows release, then close only those windows."""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import time

U = ctypes.WinDLL("user32", use_last_error=True)
K = ctypes.WinDLL("kernel32", use_last_error=True)
ENUM_CB = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
U.EnumWindows.argtypes = [ENUM_CB, wintypes.LPARAM]
U.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
U.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
U.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
K.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
K.OpenProcess.restype = wintypes.HANDLE
K.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                       ctypes.POINTER(wintypes.DWORD)]
K.CloseHandle.argtypes = [wintypes.HANDLE]


def inspector_windows(executable):
    windows = []

    @ENUM_CB
    def visit(window, _):
        title = ctypes.create_unicode_buffer(128)
        U.GetWindowTextW(window, title, len(title))
        if title.value != "XBOX-Inspector":
            return True
        pid = wintypes.DWORD()
        U.GetWindowThreadProcessId(window, ctypes.byref(pid))
        process = K.OpenProcess(0x1000, False, pid)
        if not process:
            return True
        try:
            path = ctypes.create_unicode_buffer(4096)
            size = wintypes.DWORD(len(path))
            if K.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(size)) and Path(path.value) == executable:
                windows.append(window)
        finally:
            K.CloseHandle(process)
        return True

    U.EnumWindows(visit, 0)
    return set(windows)


def wait_for(check, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise TimeoutError("Inspector window check timed out")


def smoke(root, scratch):
    executable = (root / "bin/XBOX-Inspector.exe").resolve(strict=True)
    launcher = (root / "Start-XBOX-Inspector.cmd").resolve(strict=True)
    assert not any(c in str(launcher) for c in '%!^&|<>"')
    cfg = scratch / "XBOX-Inspector"
    cfg.mkdir(parents=True)
    baseline = inspector_windows(executable)
    env = dict(os.environ, APPDATA=str(scratch.resolve()), XBS_SMOKE_HIDDEN="1")
    results = []
    for lang in ("en", "ru", "zh-Hans", "kk"):
        for theme in ("system", "light", "dark"):
            (cfg / "settings.json").write_text(json.dumps({"lang": lang, "theme": theme}), encoding="utf8")
            result = subprocess.run([env["COMSPEC"], "/d", "/c", str(launcher)], cwd=root,
                                    env=env, creationflags=subprocess.CREATE_NO_WINDOW,
                                    timeout=10, check=True)
            windows = wait_for(lambda: inspector_windows(executable) - baseline, 15)
            assert len(windows) == 1 and result.returncode == 0
            window, = windows
            assert U.PostMessageW(window, 0x0010, 0, 0)  # WM_CLOSE to verified package window
            wait_for(lambda: window not in inspector_windows(executable), 10)
            results.append({"locale": lang, "theme": theme, "created_and_closed": True})
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("scratch", type=Path)
    args = parser.parse_args()
    print(json.dumps({"hidden_launcher_smoke": smoke(args.root.resolve(strict=True), args.scratch)}, indent=2))
