"""Shared helpers for the experiments: federation builders, statistics, plotting."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import matplotlib                                     # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt                       # noqa: E402

from hfselap import HFSELAP, Config                   # noqa: E402

RESULTS = ROOT / "results"
FIGURES = RESULTS / "figures"
RESULTS.mkdir(exist_ok=True)
FIGURES.mkdir(exist_ok=True)

REGIONS = ["Region-A", "Region-B", "Region-C", "Region-D"]

# Categorical palette (fixed order) + text/grid tokens; validated reference palette
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
SERIES = [BLUE, ORANGE, AQUA, YELLOW]
MARKERS = ["o", "s", "^", "D"]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

# Power model of the base paper: Raspberry Pi 5 at full CPU load (W)
PI5_POWER_W = 7.029


def load_config() -> Config:
    return Config.load(ROOT / "config.json")


def build_federation(n_tas: int, cfg: Config | None = None, seed: int = 1,
                     monitor_mode: str = "heartbeat", same_region: bool = False,
                     trust: float = 0.9) -> HFSELAP:
    """n Regional TAs (one per region unless ``same_region``) with mutual trust."""
    s = HFSELAP(cfg or load_config(), seed=seed, monitor_mode=monitor_mode)
    for i in range(n_tas):
        s.add_ta(f"RTA-{i + 1}", REGIONS[0] if same_region else REGIONS[i])
    names = list(s.root.tas)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            s.trust(a, b, trust)
    return s


def cpu_name() -> str:
    """Human-readable processor name (Windows / Linux / macOS), best effort."""
    import platform
    import subprocess
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_Processor).Name"],
                                 capture_output=True, text=True, timeout=30).stdout.strip()
        elif platform.system() == "Darwin":
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True, timeout=30).stdout.strip()
        else:
            out = next((line.split(":", 1)[1].strip()
                        for line in open("/proc/cpuinfo", encoding="utf-8")
                        if line.startswith("model name")), "")
        return out or platform.processor()
    except Exception:                                  # pragma: no cover
        return platform.processor()


def stats(values) -> dict:
    a = np.asarray(values, dtype=float)
    n = len(a)
    sd = float(a.std(ddof=1)) if n > 1 else 0.0
    half = 1.96 * sd / math.sqrt(n) if n > 1 else 0.0
    return {"mean": float(a.mean()), "sd": sd, "median": float(np.median(a)),
            "ci95": [float(a.mean() - half), float(a.mean() + half)], "n": n}


def save_json(name: str, data):
    path = RESULTS / f"{name}.json"
    path.write_text(json.dumps(data, indent=2, default=_jsonable), encoding="utf-8")
    return path


def load_json(name: str):
    return json.loads((RESULTS / f"{name}.json").read_text(encoding="utf-8"))


def _jsonable(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, set):
        return sorted(o)
    raise TypeError(type(o))


# ------------------------------------------------------------------ plotting
def style():
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 9, "axes.titlesize": 10,
        "axes.labelsize": 9, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
        "axes.titlecolor": INK, "xtick.color": INK2, "ytick.color": INK2,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "grid.linestyle": "-", "axes.spines.top": False, "axes.spines.right": False,
        "legend.frameon": False, "legend.fontsize": 8, "lines.linewidth": 2.0,
        "lines.markersize": 5, "figure.dpi": 100, "savefig.dpi": 200,
        "axes.axisbelow": True, "figure.facecolor": "white", "axes.facecolor": "white",
    })


def new_figure(width: float = 6.4, height: float = 3.4):
    style()
    fig, ax = plt.subplots(figsize=(width, height))
    return fig, ax


def save_figure(fig, name: str):
    fig.tight_layout()
    path = FIGURES / f"{name}.png"
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path
