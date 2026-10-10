"""Windows fix for gltest direct mode.

gltest calls os.unlink() on a temp file that is still open (PermissionError, WinError 32 on
Windows). This script wraps that call in try/except OSError inside the installed package.
Run once:  python scripts/patch_gltest_windows.py
"""
import pathlib
import re

import gltest.direct.loader as m

p = pathlib.Path(m.__file__)
s = p.read_text(encoding="utf-8")
if "WINDOWS_UNLINK_PATCH" in s:
    print("already patched:", p)
else:
    s, n = re.subn(
        r"(?m)^([ \t]*)os\.unlink\(path\)[ \t]*$",
        r"\1try:  # WINDOWS_UNLINK_PATCH\n\1    os.unlink(path)\n\1except OSError:\n\1    pass",
        s,
    )
    p.write_text(s, encoding="utf-8")
    print("patched", n, "occurrence(s) in", p)
