"""Render animated terminal GIFs of real `rf` command output.

Runs each demo command, captures its ANSI-coloured output, and draws it frame by
frame (typed prompt, then lines appearing) with Pillow. No external recorder,
no browser, deterministic output, works on Windows.

    python tools/make_demo_gifs.py            # all demos -> docs/demo/*.gif
    python tools/make_demo_gifs.py lab-status # one demo
    python tools/make_demo_gifs.py --cached   # re-render from the last captured output
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "demo"
FONT_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]
COLS = 100
FONT_SIZE = 15
PAD = 18
BG = (24, 26, 32)
FG = (214, 218, 224)
PROMPT = (120, 200, 120)
DIM = (130, 136, 148)

# 16-colour ANSI palette (One Dark-ish) + a few 256-colour fallbacks
PALETTE = {
    30: (40, 44, 52), 31: (224, 108, 117), 32: (152, 195, 121), 33: (229, 192, 123),
    34: (97, 175, 239), 35: (198, 120, 221), 36: (86, 182, 194), 37: (214, 218, 224),
    90: (130, 136, 148), 91: (224, 108, 117), 92: (152, 195, 121), 93: (229, 192, 123),
    94: (97, 175, 239), 95: (198, 120, 221), 96: (86, 182, 194), 97: (255, 255, 255),
}  # fmt: skip
_ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def _strip_non_sgr(line: str) -> str:
    """Remove control sequences that are not colour/style (cursor hide, erase line)."""
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-lnp-~]", "", line)


@dataclass
class Demo:
    name: str
    command: list[str]
    title: str
    max_lines: int = 40
    hold_ms: int = 3500


DEMOS = [
    Demo("rules-stats", ["rf", "rules", "stats"], "Compile every SigmaHQ Windows rule", max_lines=34),
    Demo("coverage", ["rf", "coverage", "run", "--tactic", "credential-access", "--out", "runs/demo"],
         "Replay labelled attack telemetry, measure ATT&CK coverage"),
    Demo("lab-status", ["rf", "lab", "status"], "Live lab sensors"),
    Demo("lab-collect", ["rf", "lab", "collect", "ubuntu", "--detect"], "Pull live telemetry and run the rules", max_lines=30),
    Demo("harden", ["rf", "harden", "check", "ubuntu", "--no-save"], "Hardening posture with CIS references"),
    Demo("bench", ["rf", "bench", "report"], "LLM SOC-analyst leaderboard", max_lines=20),
]


CACHE = ROOT / "tools" / ".demo-cache"
_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")  # any control sequence, not only colours
_SPINNER = re.compile(r"^[⠀-⣿]\s")
_PROGRESS = re.compile(r"(\d+ events, \d+ alerts|^alerts$|^events, \d+ alerts?$|^\d+ alerts?$|\.evtx\] \d+ events)")


def clean(output: str) -> list[str]:
    """Drop rich status-spinner frames (non-TTY capture repeats them) and
    collapse trailing blank lines."""
    out: list[str] = []
    # rich redraws status frames with a bare CR; treat it as a line break
    for raw in output.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        text = _CSI.sub("", raw).lstrip()
        if _SPINNER.match(text) or text.endswith("...") and len(text) < 60:
            continue
        # fragments of wrapped progress-status lines ("... 9 events, 3 alerts")
        if "|" not in text and _PROGRESS.search(text):
            continue
        # keep colour codes, drop cursor show/hide and other non-SGR sequences
        out.append(_strip_non_sgr(raw).rstrip())
    while out and not out[-1].strip():
        out.pop()
    while out and not out[0].strip():
        out.pop(0)
    return out


def run(cmd: list[str], name: str, *, cached: bool) -> str:
    CACHE.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE / f"{name}.ansi"
    if cached and cache_file.exists():
        return cache_file.read_text(encoding="utf-8")
    env = dict(os.environ)
    env.update({"FORCE_COLOR": "1", "COLUMNS": str(COLS), "PYTHONIOENCODING": "utf-8", "TERM": "xterm-256color"})
    exe = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / cmd[0]
    proc = subprocess.run([str(exe), *cmd[1:]], capture_output=True, text=True, encoding="utf-8", env=env, cwd=ROOT, check=False)
    text = proc.stdout + (proc.stderr if proc.returncode else "")
    cache_file.write_text(text, encoding="utf-8")
    return text


def parse_ansi(line: str) -> list[tuple[str, tuple[int, int, int]]]:
    """Split one line into (text, colour) runs. Bold/dim handled as colour tweaks."""
    runs: list[tuple[str, tuple[int, int, int]]] = []
    colour = FG
    pos = 0
    for m in _ANSI.finditer(line):
        if m.start() > pos:
            runs.append((line[pos : m.start()], colour))
        codes = [int(c) for c in m.group(1).split(";") if c] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                colour = FG
            elif c == 1:
                colour = (255, 255, 255) if colour == FG else colour
            elif c == 2:
                colour = DIM
            elif c in PALETTE:
                colour = PALETTE[c]
            elif c == 38 and i + 2 < len(codes) and codes[i + 1] == 5:
                n = codes[i + 2]
                colour = PALETTE.get(30 + n, FG) if n < 8 else PALETTE.get(90 + n - 8, FG) if n < 16 else FG
                i += 2
            elif c == 38 and i + 4 < len(codes) and codes[i + 1] == 2:
                colour = (codes[i + 2], codes[i + 3], codes[i + 4])
                i += 4
            i += 1
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], colour))
    return runs


def load_font() -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            return ImageFont.truetype(path, FONT_SIZE)
    raise SystemExit("no monospace TTF found; edit FONT_CANDIDATES")


def render(demo: Demo, output: str, font: ImageFont.FreeTypeFont) -> Path:
    lines = clean(output)[: demo.max_lines]
    cw = font.getlength("M")
    lh = FONT_SIZE + 3
    width = int(PAD * 2 + cw * COLS)
    height = int(PAD * 2 + lh * (len(lines) + 2))
    prompt = "$ " + " ".join(demo.command)

    frames: list[Image.Image] = []
    durations: list[int] = []

    def frame(typed: str, shown: int, cursor: bool) -> Image.Image:
        img = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(img)
        # title bar dots
        for i, col in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            d.ellipse((PAD + i * 18, 6, PAD + i * 18 + 10, 16), fill=col)
        d.text((PAD + 70, 3), demo.title, font=font, fill=DIM)
        y = PAD + 8
        d.text((PAD, y), typed + ("▌" if cursor else ""), font=font, fill=PROMPT)
        y += lh
        for ln in lines[:shown]:
            x = float(PAD)
            for text, colour in parse_ansi(ln):
                d.text((x, y), text, font=font, fill=colour)
                x += font.getlength(text)
            y += lh
        return img

    # typing
    for i in range(0, len(prompt) + 1, 2):
        frames.append(frame(prompt[:i], 0, True))
        durations.append(35)
    frames.append(frame(prompt, 0, False))
    durations.append(500)
    # output reveal, faster for long outputs
    step = max(1, len(lines) // 25)
    for shown in range(step, len(lines) + step, step):
        frames.append(frame(prompt, min(shown, len(lines)), False))
        durations.append(60 if len(lines) > 15 else 110)
    durations[-1] = demo.hold_ms

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{demo.name}.gif"
    # quantise to a small palette for size
    frames_p = [f.quantize(colors=64, method=Image.Quantize.MEDIANCUT) for f in frames]
    frames_p[0].save(path, save_all=True, append_images=frames_p[1:], duration=durations, loop=0, optimize=True, disposal=1)
    return path


def main(argv: list[str]) -> None:
    font = load_font()
    cached = "--cached" in argv
    wanted = {a for a in argv if not a.startswith("--")} or {d.name for d in DEMOS}
    for demo in DEMOS:
        if demo.name not in wanted:
            continue
        print(f"-> {demo.name}: {' '.join(demo.command)}", flush=True)
        out = run(demo.command, demo.name, cached=cached)
        path = render(demo, out, font)
        print(f"   {path} ({path.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main(sys.argv[1:])
