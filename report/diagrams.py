"""Architecture and message-flow diagrams for the report (matplotlib, PNG)."""

from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                    # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch     # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "results" / "figures"
OUT.mkdir(parents=True, exist_ok=True)

INK, INK2 = "#0b0b0b", "#52514e"
BLUE, ORANGE, AQUA, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#6250d6"
TINT = {BLUE: "#e6f0fb", ORANGE: "#fdece4", AQUA: "#e3f6ef", VIOLET: "#ecebfa", INK2: "#f1f0ec"}


def box(ax, x, y, w, h, title, lines, color, title_size=8.6, size=7.2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.004,rounding_size=0.012",
                                linewidth=1.1, edgecolor=color, facecolor=TINT[color]))
    ax.text(x + w / 2, y + h - 0.016, title, ha="center", va="top", fontsize=title_size,
            fontweight="bold", color=INK)
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.045 - i * 0.022, line, ha="center", va="top",
                fontsize=size, color=INK2)


def arrow(ax, a, b, label="", color=INK2, both=False, style="-", rad=0.0, lx=0.0, ly=0.0):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="<|-|>" if both else "-|>", mutation_scale=9,
                                 linewidth=1.0, color=color, linestyle=style,
                                 connectionstyle=f"arc3,rad={rad}"))
    if label:
        ax.text((a[0] + b[0]) / 2 + lx, (a[1] + b[1]) / 2 + ly, label, fontsize=6.6, color=INK2,
                ha="center", va="center",
                bbox=dict(boxstyle="round,pad=0.15", facecolor="white", edgecolor="none"))


def architecture():
    fig = plt.figure(figsize=(7.0, 8.2))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    box(ax, 0.20, 0.855, 0.60, 0.125, "Federation / Root Trusted Authority",
        ["inter-TA trust matrix + RTA reliability scores",
         "sealed credential escrow + federated TID directory",
         "revocation registry (versioned)  |  audit log"], BLUE)
    box(ax, 0.36, 0.735, 0.28, 0.085, "Load balancer + health monitor",
        ["score = load, trust, latency, home", "heartbeats, fast fail-over"], VIOLET, size=6.8)
    box(ax, 0.03, 0.585, 0.30, 0.13, "Regional TA-1 (Region A)",
        ["runs SELAP steps A-2, A-3, A-5", "dual TID records <TID_o, TID_c>",
         "replay cache, revocation check", "delegated credential cache"], BLUE, size=6.8)
    box(ax, 0.67, 0.585, 0.30, 0.13, "Regional TA-2 (Region B)",
        ["runs SELAP steps A-2, A-3, A-5", "dual TID records <TID_o, TID_c>",
         "replay cache, revocation check", "delegated credential cache"], BLUE, size=6.8)
    box(ax, 0.12, 0.405, 0.25, 0.12, "UAV cluster A",
        ["arbiter PUF + fuzzy extractor", "smart card (C_U, H_U)", "SELAP step A-4"], ORANGE,
        size=6.8)
    box(ax, 0.63, 0.405, 0.25, 0.12, "UAV cluster B",
        ["arbiter PUF + fuzzy extractor", "smart card (C_U, H_U)", "SELAP step A-4"], ORANGE,
        size=6.8)
    box(ax, 0.03, 0.255, 0.94, 0.10, "Vehicles / On-Board Units",
        ["smart card login (ID, PW)  |  SELAP steps A-1 and A-6",
         "emergency data over the ASCON session channel"], AQUA)

    arrow(ax, (0.30, 0.715), (0.33, 0.855), "secure inter-TA link", BLUE, both=True, lx=-0.07)
    arrow(ax, (0.70, 0.715), (0.67, 0.855), "fetch / sync / revoke", BLUE, both=True, lx=0.07)
    arrow(ax, (0.36, 0.75), (0.33, 0.70), "", VIOLET, both=False)
    arrow(ax, (0.64, 0.75), (0.67, 0.70), "", VIOLET, both=False)
    arrow(ax, (0.245, 0.585), (0.245, 0.525), "Msg2 / Msg3", ORANGE, both=True)
    arrow(ax, (0.755, 0.585), (0.755, 0.525), "Msg2 / Msg3", ORANGE, both=True)
    arrow(ax, (0.06, 0.355), (0.06, 0.585), "", AQUA, both=True)
    ax.text(0.075, 0.47, "Msg1 / Msg4 (5G)", rotation=90, fontsize=6.6, color=INK2,
            ha="left", va="center")
    arrow(ax, (0.94, 0.355), (0.94, 0.585), "", AQUA, both=True, style="--")
    ax.text(0.925, 0.47, "cross-region / fail-over", rotation=90, fontsize=6.6, color=INK2,
            ha="right", va="center")
    arrow(ax, (0.245, 0.405), (0.245, 0.355), "", INK2, both=True)
    arrow(ax, (0.755, 0.405), (0.755, 0.355), "", INK2, both=True)
    ax.text(0.5, 0.38, "vehicle <-> UAV emergency data under the session key", fontsize=6.6,
            color=INK2, ha="center", va="center")

    mods = [("ASCON-128 AEAD", "confidentiality + integrity"),
            ("PUF + fuzzy extractor", "UAV hardware identity"),
            ("Identity / session update", "TID rotation, desync safe"),
            ("Revocation registry", "federation-wide reject"),
            ("Recovery / re-enrolment", "no network reset"),
            ("Post-quantum mode", "Ascon-80pq, 160-bit keys")]
    ax.text(0.5, 0.232, "Cross-cutting security modules", ha="center", fontsize=8.6,
            fontweight="bold", color=INK)
    for i, (t, d) in enumerate(mods):
        x = 0.03 + (i % 3) * 0.32
        y = 0.135 if i < 3 else 0.06
        box(ax, x, y, 0.30, 0.065, t, [d], INK2, title_size=7.6, size=6.6)
    ax.text(0.5, 0.025, "Evaluation layer: computation, communication, storage, energy, "
            "scalability, fault tolerance, mobility/stress, security",
            ha="center", fontsize=7.2, color=INK2, style="italic")
    path = OUT / "fig_architecture.png"
    fig.savefig(path, dpi=200, facecolor="white")
    plt.close(fig)
    return path


def message_flow():
    fig = plt.figure(figsize=(7.0, 5.6))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0.11, 1)
    ax.axis("off")
    cols = {"Vehicle V_t": 0.12, "Serving RTA": 0.42, "UAV U_k": 0.70, "Root TA": 0.91}
    colors = {"Vehicle V_t": AQUA, "Serving RTA": BLUE, "UAV U_k": ORANGE, "Root TA": BLUE}
    for name, x in cols.items():
        ax.add_patch(FancyBboxPatch((x - 0.075, 0.935), 0.15, 0.045,
                                    boxstyle="round,pad=0.004,rounding_size=0.01",
                                    edgecolor=colors[name], facecolor=TINT[colors[name]]))
        ax.text(x, 0.957, name, ha="center", va="center", fontsize=8.4, fontweight="bold")
        ax.plot([x, x], [0.17, 0.935], color="#cfcdc6", linewidth=1.0, zorder=0)

    def note(x, y, lines, ha="center"):
        for i, line in enumerate(lines):
            ax.text(x, y - i * 0.021, line, ha=ha, va="top", fontsize=6.6, color=INK2)

    def msg(a, b, y, label, style="-"):
        ax.add_patch(FancyArrowPatch((cols[a], y), (cols[b], y), arrowstyle="-|>",
                                     mutation_scale=10, linewidth=1.2, color=INK, linestyle=style))
        ax.text((cols[a] + cols[b]) / 2, y + 0.011, label, ha="center", fontsize=7.0, color=INK,
                bbox=dict(boxstyle="round,pad=0.12", facecolor="white", edgecolor="none"))

    note(0.015, 0.915, ["A-1: PID = h(ID || N_VR1)", "M_A1 = h(PID || N_VR2 || T1)",
                       "(C_A1, Tag_A1) = Enc(N_A1 || ID_U)"], ha="left")
    msg("Vehicle V_t", "Serving RTA", 0.835, "Msg1 = {TID, C_A1, Tag_A1, T1}   544 bits")
    note(0.42, 0.815, ["A-2: check T1, replay, revocation", "lookup TID in <TID_o, TID_c>",
                       "decrypt -> N_A1, ID_U"])
    msg("Serving RTA", "Root TA", 0.735, "fetch / record (only on cache miss)", style="--")
    note(0.42, 0.715, ["A-3: M_A3 = h(PID_V || N_A2 || T1)", "M_A4 = h(PID_U || C_U || T2)",
                       "Enc(N_A1 || N_A2 || M_A3)"])
    msg("Serving RTA", "UAV U_k", 0.635, "Msg2 = {C_A3, Tag_A3, T2}   672 bits")
    note(0.70, 0.615, ["A-4: K_U = Rep(PUF(C_U), H_U)", "PID_U = h(ID_U || K_U), decrypt",
                       "SK = h(N_A1 || M_A3 || M_A6)", "SKV = SK^a xor SK^b"])
    msg("UAV U_k", "Serving RTA", 0.51, "Msg3 = {C_A5, Tag_A5, T3}   416 bits")
    note(0.42, 0.49, ["A-5: decrypt -> N_A3, SKV", "M_A9 = h(PID_U || N_A3 || T3)",
                      "TID_o <- TID, TID_c <- TID_new"])
    msg("Serving RTA", "Vehicle V_t", 0.40, "Msg4 = {C_A7, Tag_A7, T4}   800 bits")
    msg("Serving RTA", "Root TA", 0.36, "TID sync (asynchronous write-through)", style="--")
    note(0.015, 0.33, ["A-6: decrypt -> N_A2, TID_new, M_A9, SKV",
                      "SK = h(N_A1 || h(PID || N_A2 || T1) || M_A9)",
                      "verify SKV, store SK, adopt TID_new"], ha="left")
    ax.add_patch(FancyArrowPatch((cols["Vehicle V_t"], 0.20), (cols["UAV U_k"], 0.20),
                                 arrowstyle="<|-|>", mutation_scale=10, linewidth=1.4, color=AQUA))
    ax.text(0.41, 0.212, "emergency data protected by ASCON under SK", ha="center", fontsize=7.2,
            color=INK, bbox=dict(boxstyle="round,pad=0.12", facecolor="white", edgecolor="none"))
    ax.text(0.5, 0.135, "Air interface: 2432 bits per authentication.  Dashed arrows are wired "
            "backhaul traffic added by the federation layer.", ha="center", fontsize=7.0,
            color=INK2, style="italic")
    path = OUT / "fig_message_flow.png"
    fig.savefig(path, dpi=200, facecolor="white")
    plt.close(fig)
    return path


if __name__ == "__main__":
    print(architecture())
    print(message_flow())
