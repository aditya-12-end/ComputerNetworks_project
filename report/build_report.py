"""Build HF-SELAP_Report.docx from the experiment results.

Run after ``python experiments/run_all.py``:
    python report/build_report.py
All numbers quoted in the Results section are read from results/*.json, so
the document always matches the latest run of the implementation.
"""

from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"
FIG = RES / "figures"
OUT = ROOT / "HF-SELAP_Report.docx"
sys.path.insert(0, str(Path(__file__).resolve().parent))

import diagrams                                                    # noqa: E402

BODY_FONT = "Times New Roman"
MATH_FONT = "Cambria Math"


def load(name):
    return json.loads((RES / f"{name}.json").read_text(encoding="utf-8"))


# ======================================================================
# document helpers
# ======================================================================
class Report:
    def __init__(self):
        self.doc = Document()
        self.fig_no = 0
        self.tab_no = 0
        self._setup()

    def _setup(self):
        sec = self.doc.sections[0]
        sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
        for side in ("left_margin", "right_margin"):
            setattr(sec, side, Cm(2.3))
        sec.top_margin, sec.bottom_margin = Cm(2.2), Cm(2.2)
        st = self.doc.styles
        normal = st["Normal"]
        normal.font.name = BODY_FONT
        normal.font.size = Pt(11)
        normal.element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
        normal.paragraph_format.space_after = Pt(4)
        normal.paragraph_format.line_spacing = 1.12
        for name, size in (("Heading 1", 13), ("Heading 2", 11.5), ("Heading 3", 11)):
            h = st[name]
            h.font.name = BODY_FONT
            h.font.size = Pt(size)
            h.font.bold = True
            h.font.italic = name == "Heading 3"
            h.font.color.rgb = RGBColor(0, 0, 0)
            rpr = h.element.get_or_add_rPr()
            fonts = rpr.find(qn("w:rFonts"))
            if fonts is None:
                fonts = OxmlElement("w:rFonts")
                rpr.append(fonts)
            for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
                fonts.attrib.pop(qn(attr), None)        # theme fonts would override ours
            for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
                fonts.set(qn(attr), BODY_FONT)
            h.paragraph_format.space_before = Pt(12 if name == "Heading 1" else 8)
            h.paragraph_format.space_after = Pt(4)
            h.paragraph_format.keep_with_next = True
        self._footer_page_numbers()

    def _footer_page_numbers(self):
        p = self.doc.sections[0].footer.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run()
        for tag, text in (("begin", None), (None, "PAGE"), ("end", None)):
            if tag:
                el = OxmlElement("w:fldChar")
                el.set(qn("w:fldCharType"), tag)
            else:
                el = OxmlElement("w:instrText")
                el.set(qn("xml:space"), "preserve")
                el.text = text
            run._r.append(el)
        run.font.size = Pt(9)

    # ------------------------------------------------------------ text
    TOKEN = re.compile(r"(\*\*.+?\*\*|_\{[^}]*\}|\^\{[^}]*\}|`[^`]+`)")

    def rich(self, paragraph, text, size=None, italic=False):
        for part in self.TOKEN.split(text):
            if not part:
                continue
            if part.startswith("**"):
                run = paragraph.add_run(part[2:-2])
                run.bold = True
            elif part.startswith("_{"):
                run = paragraph.add_run(part[2:-1])
                run.font.subscript = True
            elif part.startswith("^{"):
                run = paragraph.add_run(part[2:-1])
                run.font.superscript = True
            elif part.startswith("`"):
                run = paragraph.add_run(part[1:-1])
                run.font.name = "Consolas"
                run.font.size = Pt(9.5)
            else:
                run = paragraph.add_run(part)
            if size and not part.startswith("`"):
                run.font.size = Pt(size)
            if italic:
                run.italic = True
        return paragraph

    def p(self, text, align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=None, italic=False, after=None):
        para = self.doc.add_paragraph()
        para.alignment = align
        if after is not None:
            para.paragraph_format.space_after = Pt(after)
        return self.rich(para, text, size, italic)

    def eq(self, text):
        para = self.doc.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        para.paragraph_format.space_after = Pt(3)
        self.rich(para, text)
        for run in para.runs:
            run.font.name = MATH_FONT
            run.element.rPr.rFonts.set(qn("w:hAnsi"), MATH_FONT)
            run.font.size = Pt(10.5)
        return para

    def bullets(self, items, style="List Bullet"):
        for it in items:
            para = self.doc.add_paragraph(style=style)
            para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            para.paragraph_format.space_after = Pt(2)
            self.rich(para, it)

    def h1(self, text):
        self.doc.add_heading(text, level=1)

    def h2(self, text):
        self.doc.add_heading(text, level=2)

    def h3(self, text):
        self.doc.add_heading(text, level=3)

    # ---------------------------------------------------------- floats
    def figure(self, path, caption, width_cm=15.5):
        self.fig_no += 1
        self.doc.add_picture(str(path), width=Cm(width_cm))
        pic = self.doc.paragraphs[-1]
        pic.alignment = WD_ALIGN_PARAGRAPH.CENTER
        pic.paragraph_format.keep_with_next = True
        cap = self.doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        self.rich(cap, f"**Fig. {self.fig_no}.** {caption}", size=9.5)
        return self.fig_no

    def table(self, caption, header, rows, widths_cm, font=9, align_first_left=True):
        self.tab_no += 1
        cap = self.doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap.paragraph_format.keep_with_next = True
        cap.paragraph_format.space_before = Pt(6)
        self.rich(cap, f"**Table {self.tab_no}.** {caption}", size=9.5)
        t = self.doc.add_table(rows=1 + len(rows), cols=len(header))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        for r_i, row in enumerate([header] + rows):
            for c_i, val in enumerate(row):
                cell = t.rows[r_i].cells[c_i]
                cell.width = Cm(widths_cm[c_i])
                para = cell.paragraphs[0]
                para.paragraph_format.space_after = Pt(0)
                para.paragraph_format.line_spacing = 1.0
                para.alignment = (WD_ALIGN_PARAGRAPH.LEFT if (c_i == 0 and align_first_left)
                                  or len(str(val)) > 28 else WD_ALIGN_PARAGRAPH.CENTER)
                self.rich(para, str(val), size=font)
                if r_i == 0:
                    for run in para.runs:
                        run.bold = True
                    shd = OxmlElement("w:shd")
                    shd.set(qn("w:val"), "clear")
                    shd.set(qn("w:color"), "auto")
                    shd.set(qn("w:fill"), "E7E6E2")
                    cell._tc.get_or_add_tcPr().append(shd)
        # repeat header row on page breaks
        trpr = t.rows[0]._tr.get_or_add_trPr()
        hdr = OxmlElement("w:tblHeader")
        hdr.set(qn("w:val"), "true")
        trpr.append(hdr)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return self.tab_no

    def page_break(self):
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def _pretty_noise(key: str) -> str:
    """'noise=0.03, reads=1' -> '3 % noise, 1 read'."""
    parts = dict(item.strip().split("=") for item in key.split(","))
    reads = int(parts["reads"])
    return f"{float(parts['noise']) * 100:g} % noise, {reads} read{'s' if reads > 1 else ''}"


def f(x, d=2):
    return f"{x:,.{d}f}"


# ======================================================================
# content
# ======================================================================
def build():
    diagrams.architecture()
    diagrams.message_flow()
    e1, e2, e3 = load("e1_primitives"), load("e2_cost"), load("e3_overhead")
    e5, e6, e7 = load("e5_scalability"), load("e6_fault"), load("e7_mobility")
    e8, e9, e10 = load("e8_puf"), load("e9_revocation"), load("e10_security")
    env = load("environment")

    sel = e2["SELAP baseline (single TA)"]
    intra = e2["HF-SELAP intra-region"]
    cross = e2["HF-SELAP cross-region (delegated)"]
    pq = e2["HF-SELAP post-quantum (Ascon-80pq)"]
    pq_delta = 100.0 * (pq["total_ms"] - intra["total_ms"]) / intra["total_ms"]
    power = e2["_meta"]["power_model_W"]

    sc = e5["configs"]
    sc_names = list(sc)
    top_rate = e5["rates"][-1]

    def at_rate(name, rate):
        return next(p for p in sc[name] if p["offered_rate"] == rate)

    def capacity(name, thr=0.99):
        ok = [p["offered_rate"] for p in sc[name] if p["success_rate"] >= thr]
        return max(ok) if ok else 0

    sel_top = at_rate(sc_names[0], top_rate)
    static_top = at_rate(sc_names[1], top_rate)
    lb2_top = at_rate(sc_names[2], top_rate)
    lb3_top = at_rate(sc_names[3], top_rate)

    fc = e6["configs"]
    f_sel, f_static, f_hf = (fc[k] for k in fc)
    detect_s = (f_hf["detections_ms"][0][1] - e6["fail_at_ms"]) / 1000.0 if f_hf["detections_ms"] else None

    mob = e7["configs"]
    m_names = list(mob)
    m_top = {k: v[-1] for k, v in mob.items()}
    top_speed = e7["speeds"][-1]

    rep7 = e8["curves"]["7"]["empirical"]
    noise_idx = e8["noises"].index(0.03)
    i4 = e8["noises"].index(0.04)
    rev_rows = e9["rows"]
    rev_big = rev_rows[-1]
    blocked, total = e10["blocked"], e10["total"]

    R = Report()
    doc = R.doc

    # ------------------------------------------------------------- title
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    t.paragraph_format.space_after = Pt(10)
    run = t.add_run("HF-SELAP: A Hierarchical Federated Lightweight Authentication Framework "
                    "for Secure UAV-Assisted VANET Communication in Disaster Rescue")
    run.bold = True
    run.font.size = Pt(16)
    a = doc.add_paragraph()
    a.alignment = WD_ALIGN_PARAGRAPH.CENTER
    a.paragraph_format.space_after = Pt(2)
    r = a.add_run("Vansh Garg (24BCI0132)    |    Aditya Bhatt (24BCI0143)")
    r.font.size = Pt(11.5)
    r.bold = True
    c = doc.add_paragraph()
    c.alignment = WD_ALIGN_PARAGRAPH.CENTER
    c.paragraph_format.space_after = Pt(14)
    r = c.add_run("BCSE308L – Computer Networks  •  Project Report")
    r.italic = True
    r.font.size = Pt(10.5)

    # ---------------------------------------------------------- abstract
    R.h1("Abstract")
    R.p(
        "When an earthquake, flood or wildfire destroys roadside units and cellular towers, "
        "unmanned aerial vehicles (UAVs) can restore connectivity for stranded vehicles. Their "
        "radio links are open, though, and the devices on both ends have little processing power, "
        "so the authentication scheme must be both strong and cheap. SELAP, a recent lightweight "
        "protocol built from ASCON authenticated encryption, hash functions and physical "
        "unclonable functions (PUFs), meets those two goals. However, it depends on a single "
        "trusted authority (TA), and it does not handle overload, authority failure, compromised "
        "devices or the move to quantum-resistant parameters. This work proposes and implements "
        "**HF-SELAP**, a hierarchical federated extension. HF-SELAP keeps SELAP's four-message "
        "exchange unchanged on the radio interface. Behind it, the work is spread over several "
        "Regional TAs coordinated by a Root/Federation TA. Around this core it adds load "
        "balancing, heartbeat-based fail-over, a federated revocation registry, recovery by "
        "re-enrolment and an Ascon-80pq post-quantum mode. The complete system was implemented "
        "in Python. That includes a from-scratch ASCON verified against the reference "
        "implementation, a simulated arbiter PUF with a code-offset fuzzy extractor, and a "
        "discrete-event network simulator. "
        f"Measured results show {f(intra['vehicle']['mean'], 3)} ms of computation on the vehicle "
        f"and {f(intra['uav']['mean'], 3)} ms on the UAV per authentication, with exactly 2432 "
        f"bits on the air interface. Under a 70 % hot-spot load of {top_rate} requests/s, three "
        f"load-balanced Regional TAs authenticated {f(100 * lb3_top['success_rate'], 1)} % of "
        f"requests, against {f(100 * sel_top['success_rate'], 1)} % for a single TA. While a "
        f"Regional TA was down, {f(f_hf['outage_timely_pct'], 1)} % of requests were still "
        f"served within one second, against {f(f_sel['outage_timely_pct'], 1)} % without "
        f"federation. All {total} implemented attack scenarios were blocked, and the "
        f"post-quantum mode changed the total computation by only {f(pq_delta, 1)} %.")
    kw = doc.add_paragraph()
    kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    R.rich(kw, "**Keywords:** UAV-assisted VANET, Lightweight authentication, ASCON, "
               "Physical unclonable function, Federated trust management, Disaster communication")

    # ------------------------------------------------------ introduction
    R.h1("1. Introduction")
    R.p(
        "Large disasters cut off exactly the communication services that rescue teams depend on. "
        "Fallen towers, flooded cabinets and power outages leave roadside units, base stations and "
        "Wi-Fi access points unusable for hours or days, while people in vehicles still need route "
        "guidance, hazard warnings and a way to report casualties. Vehicular ad hoc networks "
        "(VANETs) let vehicles exchange this information, but in a damaged area they need a "
        "temporary backbone. UAVs suit this role well. They can be launched within minutes, "
        "placed over the affected road segments, and moved as the situation changes [9], [16], [17].")
    R.p(
        "Putting UAVs into the communication path creates its own security problems. Every frame "
        "between a vehicle, a UAV and the coordinating trusted authority crosses an open wireless "
        "channel, so it can be eavesdropped, replayed, altered or blocked. A UAV can be shot down "
        "or captured, and an attacker who reads its memory could then forge rescue instructions. "
        "On-board units and UAV flight computers have limited computation and energy, so schemes "
        "that rely on many elliptic-curve or pairing operations per session are poorly matched to "
        "the task [6], [14]. Finally, people expect their identity and movements to stay private, "
        "even during an emergency.")
    R.p(
        "SELAP, the base protocol of this project [21], answers these concerns with a careful "
        "combination of symmetric primitives. All protocol messages are protected by the "
        "lightweight AEAD scheme ASCON [22]. UAV identities are tied to PUF responses that are "
        "stabilised by a fuzzy extractor. A pair of old and current temporary identities kept "
        "at the TA prevents desynchronisation. The result is a four-message exchange of only "
        "2432 bits. The SELAP authors themselves point out the limits of the design: everything "
        "depends on one trusted authority, robustness under heavy load and high mobility has not "
        "been examined, compromised entities cannot be revoked and rehabilitated, and migration "
        "to post-quantum primitives is left open.")
    R.p("This project turns those open points into a working system. Its contributions are:")
    R.bullets([
        "**A hierarchical federated architecture (HF-SELAP).** Regional TAs run the SELAP "
        "exchange for their regions. A Root/Federation TA keeps inter-TA trust, a sealed "
        "credential escrow and a federated identity directory, so any trusted Regional TA can "
        "serve a foreign vehicle or UAV without new radio messages.",
        "**Availability mechanisms.** A load balancer scores Regional TAs by queue length, "
        "reliability, latency and locality. A heartbeat monitor detects failed TAs and fails over "
        "to healthy ones, and recovered TAs are resynchronised automatically.",
        "**Life-cycle security.** A versioned, federation-wide revocation registry is pushed to "
        "every Regional TA. Recovery by re-enrolment issues fresh credentials (or a fresh PUF "
        "challenge) to one entity without a network reset. An optional post-quantum mode "
        "switches to Ascon-80pq with 160-bit keys.",
        "**A complete, tested implementation and evaluation.** The evaluation covers computation, "
        "communication, storage, energy, scalability, fault tolerance, mobility, PUF reliability "
        f"and {total} executable attack scenarios, all reproducible from the published scripts.",
    ])
    R.p(
        "The rest of the report is organised as follows. Section 2 surveys related work, Section 3 "
        "presents the architecture, Section 4 details the methodology and implementation, Section 5 "
        "reports and discusses the results, and Section 6 concludes.")

    # ---------------------------------------------------- literature
    R.h1("2. Literature Survey")
    R.p(
        "The surveyed work falls into five groups: reliable vehicular messaging, lightweight and "
        "privacy-preserving VANET authentication, hardware-rooted security, UAV-assisted emergency "
        "networking, and survey studies. For each group we note what carries over to a "
        "UAV-supported disaster setting and what is still missing.")
    R.h2("2.1 Reliable dissemination of safety messages")
    R.p(
        "Nwizege et al. [1] studied DSRC vehicle-to-infrastructure safety messaging and proposed "
        "ACARS, a rate-selection algorithm that uses vehicle speed and context to adapt the "
        "transmission rate. Their simulations show higher throughput and shorter delay in "
        "fast-moving traffic, but security is not part of the design and the results are not "
        "validated in the field. Fogue et al. [12] secured warning dissemination through "
        "cooperative neighbour position verification. Before relaying an alert, vehicles check "
        "where their neighbours claim to be, which raised dissemination performance by up to "
        "50 % under false-position attacks. The method depends on honest cooperation and does "
        "not authenticate the senders themselves. Jing et al. [15] proposed EABA, which assigns "
        "priorities to messages and lets vehicles and roadside units share batch verification, "
        "lowering delay and loss in dense traffic. Chim et al. [7] proposed MLAS, which separates "
        "routine messages verified with HMACs from urgent messages that receive stronger "
        "verification and reports large reductions in verification delay. Both of the last two "
        "schemes still rely on roadside units, exactly the infrastructure a disaster removes.")
    R.h2("2.2 Lightweight and privacy-preserving VANET authentication")
    R.p(
        "Hsieh et al. [2] built ECC-based group key agreement for V2V and V2I groups and added a "
        "delay-based flooding rule that reduces broadcast collisions. Frequent membership changes, "
        "however, force costly re-keying. Theodore et al. [8] combined an improved TESLA broadcast "
        "authentication with a cuckoo filter, achieving mutual authentication, anonymity and "
        "revocation support with small memory. Gao et al. [11] integrated pseudonyms, group "
        "signatures and identity-based cryptography into PMIPv6 so that handovers stay anonymous "
        "and cheap, but they leave inter-domain trust to future work. Thorncharoensri et al. [10] "
        "replaced attribute-based access control with level-based signcryption, which gives "
        "constant-size ciphertexts but no efficient credential revocation. Wang et al. [19] "
        "proposed HDMA for 5G-enabled VANETs, using group signatures, pseudonyms and pre-computed "
        "tables to avoid pairings. Shawky et al. [13] extracted keys with Chebyshev chaotic maps "
        "and added physical-layer checks, keeping authentication reliable down to 0 dB SNR at "
        "45 m/s. Tan and Chung [20] used a consortium blockchain, edge computing and the Chinese "
        "Remainder Theorem for certificateless authentication and dynamic group keys, at the cost "
        "of consensus and storage overhead. All of these schemes target conventional VANETs. None "
        "considers UAV relays or the loss of the trusted infrastructure itself.")
    R.h2("2.3 Hardware-rooted and physically secure authentication")
    R.p(
        "Alfadhli et al. [4] proposed MFSPV, a multi-factor scheme in which PUFs and one-time "
        "dynamic pseudonyms protect V2V and V2I exchanges against cloning, impersonation and "
        "replay. The design assumes dependable PUF hardware and trusted regional certificate "
        "authorities. Aghabagherloo et al. [5] combined the advantages of RSU-aided and "
        "tamper-resistant-device-aided conditional privacy-preserving authentication. Their scheme "
        "keeps working, and even detects tampering, when an on-board unit is physically "
        "compromised. These works show the value of binding identity to hardware, which SELAP "
        "adopts for UAVs, but neither handles a UAV-assisted network or noisy PUF responses in a "
        "multi-authority deployment.")
    R.h2("2.4 UAV-assisted emergency communication")
    R.p(
        "On the networking side, Sona et al. [9] placed UAV relays according to population "
        "density, terrain, altitude and battery level and routed traffic energy-efficiently, "
        "reporting lower path and packet loss and more than 93 % communication efficiency. "
        "Sharvari et al. [16] designed MO3DR, an opportunistic 3D routing algorithm that picks "
        "forwarding UAVs under coverage and collision constraints. Matracia et al. [17] surveyed "
        "terrestrial, aerial and space-borne post-disaster networks, and identified backhauling, "
        "UAV placement, mobility and energy management as open problems. None of these three "
        "works includes authentication. On the security side, Aissaoui et al. [6] reviewed "
        "cryptography for UAV traffic management and concluded that mainstream Internet security "
        "standards are often too heavy for small UAVs. Lei et al. [18] proposed ODIAP for the "
        "Internet of Drones, offloading Chinese-Remainder-Theorem computations to servers and "
        "verifying the protocol with ProVerif. Cui et al. [3] designed a provably secure "
        "authentication and key agreement scheme for UAV-assisted VANETs in emergency rescue, "
        "based on chaotic maps, fuzzy verifiers and honeywords. It meets fourteen security "
        "requirements, but the honeyword store adds storage and the design keeps a single "
        "authority.")
    R.h2("2.5 Survey studies")
    R.p(
        "Jan et al. [14] classified privacy-preserving VANET authentication into pseudonym-, "
        "identity-, hash-, group-signature- and blockchain-based families. They compared the "
        "families' attack resistance and overhead, and concluded that secure, scalable and "
        "efficient mechanisms are still needed.")
    R.table("Summary of the surveyed literature",
            ["Ref.", "Core technique", "Main strength", "Gap relevant to this work"],
            [["[1]", "Context-aware rate selection (DSRC)", "Throughput and delay under mobility",
              "No security; simulation only"],
             ["[2]", "ECDH group keys, delayed flooding", "Secure group messaging, fewer collisions",
              "Costly re-keying; no UAVs"],
             ["[3]", "Chaotic maps, fuzzy verifier, honeywords", "Provable UAV-VANET AKA",
              "Single authority; honeyword storage"],
             ["[4]", "PUF + one-time pseudonyms", "Clone and impersonation resistance",
              "Needs trusted regional CAs; no UAVs"],
             ["[5]", "RSU- and TRD-aided CPPA", "Survives OBU compromise",
              "Random-oracle model; trusted TA"],
             ["[6]", "Survey of UTM cryptography", "Gap analysis for small UAVs",
              "No protocol proposed"],
             ["[7]", "HMAC for regular, strong auth for urgent", "Very low verification delay",
              "Depends on RSUs"],
             ["[8]", "Improved TESLA + cuckoo filter", "Cheap broadcast auth, revocation",
              "No UAV support"],
             ["[9]", "Optimised UAV relay placement", "Coverage and energy efficiency",
              "No authentication"],
             ["[10]", "Level-based signcryption", "Constant-size, simple access control",
              "No efficient revocation"],
             ["[11]", "PMIPv6 + pseudonyms + group signatures", "Anonymous handover",
              "No inter-domain trust"],
             ["[12]", "Cooperative position verification", "Robust warning dissemination",
              "Needs cooperative honest nodes"],
             ["[13]", "Chaotic keys + PHY-layer checks", "Low-cost re-authentication",
              "Channel-dependent; no UAVs"],
             ["[14]", "Survey of privacy-preserving auth", "Taxonomy and open issues",
              "No protocol proposed"],
             ["[15]", "Priority-based batch verification", "Lower delay in dense traffic",
              "Relies on RSU cooperation"],
             ["[16]", "Opportunistic 3D UAV routing", "Reliable multi-hop delivery",
              "No security; no energy model"],
             ["[17]", "Survey of post-disaster networks", "Architectures and challenges",
              "No protocol proposed"],
             ["[18]", "CRT-based IoD authentication", "Low UAV computation, ProVerif",
              "Server dependence; IoD only"],
             ["[19]", "Group signatures + lookup tables", "Pairing-free 5G VANET auth",
              "Trusted infrastructure; no UAVs"],
             ["[20]", "Consortium blockchain + edge + CRT", "Dynamic group keys",
              "Consensus/storage overhead"]],
            [1.1, 4.6, 4.5, 4.8])
    R.h2("2.6 Research gap")
    R.p(
        "Taken together, the literature offers efficient cryptographic building blocks and "
        "capable UAV networking schemes, but they are rarely combined. SELAP [21] closes much "
        "of this gap. It brings ASCON, PUFs, a fuzzy extractor and desynchronisation-resistant "
        "identity updates into one protocol for UAV-assisted VANETs and outperforms elliptic-curve "
        "designs in cost. What remains open is the system around the protocol: a single trusted "
        "authority is both a capacity limit and a single point of failure, compromised entities "
        "cannot be removed and re-admitted, behaviour under overload and high mobility is "
        "unknown, and there is no post-quantum path. HF-SELAP is designed to fill exactly these "
        "gaps while leaving SELAP's radio messages unchanged.")

    # ---------------------------------------------------- architecture
    R.h1("3. Proposed System Architecture")
    R.p(
        "The architecture (Fig. 1) arranges the system in layers. Vehicles and UAVs form the "
        "access layer. Regional TAs form the authentication layer. A Root/Federation TA forms the "
        "trust-coordination layer. A set of cross-cutting security modules and an evaluation "
        "layer complete the design.")
    R.figure(FIG / "fig_architecture.png",
             "HF-SELAP architecture: SELAP authentication at Regional TAs under a Root/Federation "
             "TA, with load balancing, fail-over and cross-cutting security modules.", 14.5)
    R.h2("3.1 Components and their roles")
    R.bullets([
        "**Vehicles / on-board units.** A vehicle requests emergency service, unlocks its smart "
        "card with its identity and password, and runs the two light SELAP steps (A-1 and A-6). "
        "The OBU therefore performs only hashing and two ASCON operations per session.",
        "**UAV clusters.** UAVs give coverage where ground infrastructure has failed. Each UAV "
        "carries an arbiter PUF and a fuzzy extractor, so its identity comes from its silicon and "
        "not only from stored secrets. UAVs are grouped by region so the fleet can grow.",
        "**Regional TAs (RTAs).** Each RTA manages the vehicles and UAVs enrolled in its region "
        "and runs the TA side of SELAP (A-2, A-3, A-5). It keeps SELAP's dual temporary-identity "
        "records, a replay cache, the local copy of the revocation list, and a cache of "
        "credentials delegated by the federation.",
        "**Federation / Root TA.** The Root TA authorises the RTAs, maintains the inter-TA trust "
        "matrix and per-RTA reliability scores, stores a sealed escrow copy of every entity's "
        "credentials, and keeps a federated directory of temporary identities. It mediates every "
        "cross-region, load-sharing or fail-over request.",
        "**Load balancer.** When a request arrives, the load balancer chooses among the healthy, "
        "trusted RTAs by queue occupancy, reliability, expected latency and locality, so that a "
        "disaster hot-spot does not overload a single RTA.",
        "**Fault-tolerance procedure.** RTAs send heartbeats. A missing heartbeat, or a timeout "
        "together with a missing heartbeat, marks an RTA as down, and its traffic moves to "
        "another trusted RTA. A recovered RTA is resynchronised by the Root TA.",
        "**ASCON AEAD security layer.** Every protocol message, every inter-TA message and the "
        "post-authentication data channel are protected by ASCON, which gives confidentiality and "
        "integrity at low cost.",
        "**PUF and fuzzy extractor.** The fuzzy extractor turns the noisy PUF response into the "
        "same key every time. A cloned smart card on a different chip, or a UAV whose PUF has "
        "been tampered with, therefore cannot authenticate.",
        "**Identity and session update.** Each successful run replaces the vehicle's temporary "
        "identity. The old and current values are both accepted, so lost messages cannot cause "
        "desynchronisation, and the update is pushed to the federation.",
        "**Revocation registry.** Compromised or retired vehicles and UAVs are recorded in a "
        "versioned registry at the Root TA. The registry is pushed to every RTA, and RTAs that "
        "were offline catch up when they rejoin.",
        "**Recovery / re-enrolment.** A revoked or damaged entity is re-admitted with new "
        "credentials (or a new PUF challenge-response pair) while every other entity keeps "
        "working, so the network never needs a reset.",
        "**Post-quantum lightweight layer.** A configuration switch moves all AEAD operations to "
        "Ascon-80pq with 160-bit keys, raising resistance to quantum key search without changing "
        "message formats.",
        "**Evaluation layer.** The design is measured for authentication speed, traffic, "
        "computation, storage, energy and security, under high mobility, changing link "
        "conditions, overload and failures.",
    ])
    R.h2("3.2 Operational workflow")
    R.bullets([
        "**Step 1 – Enrolment.** Each vehicle and UAV registers once with an RTA of its region over "
        "a secure provisioning channel. The UAV's PUF is measured, helper data is produced, and "
        "the RTA deposits a sealed copy of the credentials with the Root TA.",
        "**Step 2 – Request routing.** An authentication request is directed by the load balancer "
        "to the best healthy and trusted RTA. This is normally the home RTA, but another RTA when "
        "the home RTA is busy, failed or far away.",
        "**Step 3 – Vehicle request.** The vehicle builds Msg1 from a fresh nonce, a timestamp and "
        "its temporary identity, protected with an ASCON key derived from its secrets.",
        "**Step 4 – TA verification and UAV contact.** The RTA checks freshness, replays and "
        "revocation, and recovers the requested UAV. If the vehicle or UAV belongs to another "
        "region, the RTA obtains its credentials from the Root TA over an authenticated "
        "inter-TA link. It then sends Msg2 to the UAV.",
        "**Step 5 – Key agreement.** The UAV regenerates its PUF key, authenticates the RTA, "
        "derives the session key and returns Msg3. The RTA authenticates the UAV, rotates the "
        "vehicle's temporary identity and sends Msg4. The vehicle derives the same session key "
        "and confirms it with the verifier.",
        "**Step 6 – Revocation.** A compromised entity is entered in the federated revocation "
        "registry, and all RTAs then reject its requests.",
        "**Step 7 – Recovery.** A legitimate entity whose credentials were lost or revoked is "
        "re-enrolled with fresh credentials, without disturbing anyone else.",
        "**Step 8 – Fail-over and load sharing.** When an RTA fails or saturates, requests are "
        "handled by other RTAs using delegated credentials. When it returns, it is resynchronised.",
        "**Step 9 – Evaluation.** The complete system is measured under high mobility, lossy links, "
        "overload and failures to show that it works in practice.",
    ])
    R.h2("3.3 Mapping to the open issues of SELAP")
    R.table("SELAP limitations and how HF-SELAP addresses them",
            ["Limitation stated for SELAP [21]", "HF-SELAP mechanism", "Evaluated in"],
            [["Single TA limits scale in large or multi-domain deployments",
              "Regional TAs + Root TA, delegated authentication, load balancing", "Sec. 5.6"],
             ["Single TA is a single point of failure",
              "Heartbeat monitoring, fail-over, resynchronisation", "Sec. 5.7"],
             ["Robustness under stress and high mobility not examined",
              "Event simulation with loss, queues, retries and moving vehicles", "Sec. 5.6–5.8"],
             ["PUF / fuzzy extractor adds management complexity",
              "Majority-voted enrolment, re-read on failure, PUF re-enrolment", "Sec. 5.9"],
             ["No revocation or recovery of compromised entities",
              "Federated revocation registry, re-enrolment protocol", "Sec. 5.10"],
             ["No post-quantum migration path",
              "Ascon-80pq mode with 160-bit keys", "Sec. 5.3"]],
            [6.2, 6.6, 2.2])

    # ---------------------------------------------------- methodology
    R.h1("4. Proposed Methodology")
    R.h2("4.1 System and threat model")
    R.p(
        "The system contains vehicles V_{t}, UAVs U_{k}, a set of Regional TAs and one Root TA. "
        "Vehicles and UAVs carry smart cards issued during enrolment. Each UAV also contains a "
        "PUF. The attacker follows the Dolev–Yao model: it controls every public channel and can "
        "read, delete, delay, replay, modify and inject messages. Following the Canetti–Krawczyk "
        "extension used by SELAP, it may also learn ephemeral values, steal a smart card and read "
        "its contents, and try to guess passwords, but it cannot obtain a card's secrets and the "
        "matching password at the same time. Trusted authorities may crash, which is the failure "
        "case HF-SELAP adds, but they are not malicious. Inter-TA links run over a wired backhaul "
        "and are protected by per-RTA ASCON link keys issued by the Root TA. Clocks are loosely "
        "synchronised, and a message is accepted only if its timestamp is within ΔT of the "
        "receiver's clock.")
    R.table("Notation", ["Symbol", "Meaning"],
            [["ID_{V}, PW_{V} / ID_{U}, PW_{U}", "Identity and password of a vehicle / UAV"],
             ["PID_{V}, PID_{U}", "Pseudonymous identities (hash of identity and secret)"],
             ["TID_{V}, TID^{o}, TID^{c}", "Temporary vehicle identity; old and current TA records"],
             ["k_{TA}", "Private master key of a Regional TA"],
             ["C_{U}, RS_{U}, K_{U}, H_{U}", "PUF challenge, response, extracted key, helper data"],
             ["N_{x}, T_{x}", "128-bit nonce, 32-bit timestamp"],
             ["M_{x}, M^{a}, M^{b}", "256-bit credential and its two 128-bit halves"],
             ["h(·), ⊕, ∥", "SHA-256, bitwise XOR, concatenation"],
             ["Enc_{k}/Dec_{k}", "ASCON authenticated encryption / decryption"],
             ["SK, SKV", "Session key and its 128-bit verifier SK^{a} ⊕ SK^{b}"]],
            [5.2, 9.8])
    R.h2("4.2 Cryptographic building blocks")
    R.p(
        "**ASCON.** All authenticated encryption uses ASCON-128 [22] (or Ascon-80pq in "
        "post-quantum mode). Following SELAP, every ASCON instance is keyed from a 256-bit "
        "credential M that both parties can compute, so no key is ever transmitted:")
    R.eq("IV = M^{a},   AD = M^{b},   k = M^{a} ⊕ M^{b}")
    R.p(
        "In post-quantum mode the 160-bit key is k = Trunc_{160}(h(\"HF-SELAP-PQ\" ∥ M)). IV and "
        "AD are unchanged. A tag mismatch makes the receiver abort, which gives integrity and "
        "implicit authentication in one step.")
    R.p(
        "**PUF.** Each UAV has an arbiter PUF modelled with the additive delay model: 65 "
        "device-specific delay parameters drawn once at manufacture, 64-stage sub-challenges "
        "obtained by expanding the 128-bit challenge with SHAKE-256, and one response bit per "
        "sub-challenge. Environmental noise flips each response bit independently with "
        "probability p (3 % by default).")
    R.p(
        "**Fuzzy extractor.** The code-offset construction with a repetition code of length "
        "r = 7 protects a random 128-bit secret s. Gen(R) publishes helper data H = R ⊕ Enc(s) "
        "and outputs K = h(R). Rep(R′, H) decodes s by majority vote and rebuilds R and K. At "
        "enrolment, the reference response is the bitwise majority of nine PUF reads, so a "
        "single unlucky read cannot become the reference. During authentication, the UAV "
        "re-reads the PUF (at most three times) whenever the reconstructed key fails the ASCON "
        "tag check.")
    R.h2("4.3 Registration and login")
    R.p(
        "**Vehicle registration.** The vehicle picks ID_{V} and N_{VR1} and sends "
        "PID_{V} = h(ID_{V} ∥ N_{VR1}) to its RTA. The RTA issues TID_{V} and N_{VR2}, and stores "
        "the record ⟨TID^{o} = ⊥, TID^{c} = TID_{V}, N_{VR2}, M_{VR1}⟩, where:")
    R.eq("M_{VR1} = PID_{V} ⊕ h(N_{VR2} ∥ k_{TA})")
    R.p(
        "The smart card picks N_{VR3}, stores M_{VR2} = N_{VR3} ⊕ h(ID_{V} ∥ PW_{V}), and seals "
        "N_{VR1} ∥ N_{VR2} under the key derived from M_{VR3} = h(ID_{V} ∥ PW_{V} ∥ N_{VR3}). "
        "HF-SELAP adds one step: the RTA deposits a sealed copy ⟨handle, TID^{o}, TID^{c}, "
        "N_{VR2}, PID_{V}⟩ with the Root TA over the inter-TA link.")
    R.p(
        "**UAV registration.** The RTA rejects identities already known to the federation and "
        "issues a fresh challenge C_{U}. The UAV returns its enrolment response RS_{U}. The RTA "
        "computes (K_{U}, H_{U}) = Gen(RS_{U}) and stores:")
    R.eq("PID_{U} = h(ID_{U} ∥ K_{U}),   M_{UR1} = PID_{U} ⊕ h(ID_{U} ∥ C_{U} ∥ k_{TA})")
    R.p(
        "The UAV's smart card seals C_{U} ∥ H_{U} under the operator's password, using the same "
        "construction as the vehicle card. The escrow copy deposited at the Root TA contains "
        "PID_{U} and C_{U}.")
    R.p(
        "**Login.** Entering ID and PW lets the card recover its nonce from M_{VR2} (or M_{UR2}), "
        "rebuild the ASCON key and open the sealed credentials. A wrong password fails the tag "
        "check. After five consecutive failures the card locks, which stops online guessing on a "
        "stolen card.")
    R.h2("4.4 Authentication and key agreement")
    R.p(
        "Fig. 2 shows the exchange. Steps A-1 to A-6 follow SELAP exactly, so the radio messages "
        "keep their sizes (544, 672, 416 and 800 bits).")
    R.figure(FIG / "fig_message_flow.png",
             "Message flow of one HF-SELAP authentication. Solid arrows are radio messages and "
             "dashed arrows are backhaul traffic added by the federation.", 15.0)
    R.bullets([
        "**A-1 (vehicle).** Computes PID_{V}, a nonce N_{A1}, a timestamp T_{1} and "
        "M_{A1} = h(PID_{V} ∥ N_{VR2} ∥ T_{1}), encrypts N_{A1} ∥ ID_{U}, and sends "
        "Msg1 = {TID_{V}, C_{A1}, Tag_{A1}, T_{1}}.",
        "**A-2 (RTA).** Checks |T_{R} − T_{1}| ≤ ΔT and the replay cache. Finds TID_{V} in "
        "TID^{o} or TID^{c} (fetching the record from the Root TA if it belongs to another RTA). "
        "Checks revocation, recovers PID_{V} = M_{VR1} ⊕ h(N_{VR2} ∥ k_{TA}), and decrypts Msg1 "
        "with M_{A2} = h(PID_{V} ∥ N_{VR2} ∥ T_{1}).",
        "**A-3 (RTA).** Looks up ID_{U}, recovers PID_{U}, picks N_{A2} and T_{2}, computes "
        "M_{A3} = h(PID_{V} ∥ N_{A2} ∥ T_{1}) and M_{A4} = h(PID_{U} ∥ C_{U} ∥ T_{2}), and sends "
        "Msg2 = {C_{A3}, Tag_{A3}, T_{2}} carrying N_{A1} ∥ N_{A2} ∥ M_{A3}.",
        "**A-4 (UAV).** Reads the PUF, computes K_{U} = Rep(RS′_{U}, H_{U}) and "
        "PID_{U} = h(ID_{U} ∥ K_{U}), and decrypts Msg2, which authenticates the RTA. Picks "
        "N_{A3} and T_{3}, computes M_{A6} = h(PID_{U} ∥ N_{A3} ∥ T_{3}), the session key "
        "SK = h(N_{A1} ∥ M_{A3} ∥ M_{A6}) and SKV = SK^{a} ⊕ SK^{b}, and returns "
        "Msg3 = {C_{A5}, Tag_{A5}, T_{3}}.",
        "**A-5 (RTA).** Decrypts Msg3 (authenticating the UAV), computes "
        "M_{A9} = h(PID_{U} ∥ N_{A3} ∥ T_{3}), issues TID^{new}, sets TID^{o} ← TID_{V} and "
        "TID^{c} ← TID^{new}, and sends Msg4 = {C_{A7}, Tag_{A7}, T_{4}} carrying "
        "N_{A2} ∥ TID^{new} ∥ M_{A9} ∥ SKV. The identity update is then written through to the "
        "Root TA asynchronously.",
        "**A-6 (vehicle).** Decrypts Msg4, computes SK = h(N_{A1} ∥ h(PID_{V} ∥ N_{A2} ∥ T_{1}) "
        "∥ M_{A9}), accepts only if SK^{a} ⊕ SK^{b} = SKV, and adopts TID^{new}.",
    ])
    R.h2("4.5 Federation layer")
    R.p(
        "**Secure inter-TA link.** Each RTA shares an ASCON-128 link key with the Root TA. Every "
        "inter-TA message carries a header (sender, receiver, type, sequence number, timestamp) "
        "that is authenticated as associated data. Sequence numbers must strictly increase, so "
        "inter-TA replays are rejected as well.")
    R.p(
        "**Delegated authentication.** An RTA that lacks a credential raises a fetch request. "
        "The Root TA checks that the requested identity is current, that the entity is not "
        "revoked, and that the entity's home RTA trusts the requester at or above the threshold "
        "(0.6). It then returns the record over the link. The serving RTA caches the record for "
        "60 s and runs the unchanged SELAP steps, using PID_{V} and PID_{U} directly instead of "
        "unmasking them with the home RTA's k_{TA}, which never leaves the home RTA.")
    R.p(
        "**Consistent identity updates.** After A-5 the serving RTA sends the new ⟨TID^{o}, "
        "TID^{c}⟩ pair to the Root TA, which updates the escrow and directory and forwards the "
        "change to the home RTA and to any RTA holding a cached copy. An update whose TID^{o} is "
        "no longer one of the identities the Root TA has on record is ignored. This prevents a "
        "delayed message from rolling a vehicle back to an old identity.")
    R.p("**Load balancing.** Among healthy RTAs trusted by the vehicle's home RTA, the load "
        "balancer selects the RTA with the highest score:")
    R.eq("S = 0.45 (1 − q/Q) + 0.25 ρ + 0.20 (L_{local}/L) + 0.10 [home]")
    R.p(
        "Here q/Q is queue occupancy, ρ is an exponentially weighted reliability score kept by "
        "the Root TA, L is the expected access latency (10 ms in-region, 25 ms cross-region), and "
        "[home] is 1 for the vehicle's home RTA.")
    R.p(
        "**Fault tolerance.** RTAs send a heartbeat every 500 ms. An RTA is treated as down after "
        "three missed heartbeats, or earlier if a request to it times out while at least one "
        "heartbeat is missing. A vehicle whose attempt times out (1.5 s) retries through another "
        "RTA, up to three attempts. A recovering RTA receives every revocation and identity update "
        "it missed before it serves again.")
    R.p(
        "**Revocation and recovery.** Revoking an entity adds its handle to a versioned registry "
        "and pushes a REVOKE message to every operational RTA, which drops the entity from its "
        "indexes and caches. Recovery revokes the old handle (if it is not already revoked) and "
        "registers the entity again: a vehicle receives a new temporary identity and N_{VR2}, and "
        "a UAV receives a new PUF challenge and helper data. A physically tampered PUF cannot be "
        "re-enrolled; the hardware has to be replaced.")
    R.h2("4.6 Implementation")
    R.p(
        f"HF-SELAP is written in Python {env['python']} and uses NumPy (PUF model) and Matplotlib "
        "(figures). It has no external cryptography dependency: ASCON v1.2 was implemented from "
        "the specification and agrees byte-for-byte with the published reference implementation "
        "on the official test vector and on random inputs for both variants. SHA-256 comes from "
        "the Python standard library. Table 4 lists the modules. Thirty-one unit and security "
        "tests check functional correctness, operation counts, federation behaviour and every "
        "attack scenario.")
    R.table("Implementation modules",
            ["Module", "Responsibility"],
            [["ascon.py", "ASCON-128 and Ascon-80pq AEAD (pure Python)"],
             ["primitives.py", "h(·), key derivation, 32-bit timestamps, simulated clock, op meter"],
             ["puf.py", "Arbiter PUF model and code-offset fuzzy extractor"],
             ["messages.py", "Wire formats of Msg1–Msg4 and inter-TA messages"],
             ["entities.py", "Smart cards, vehicle (A-1, A-6), UAV (A-4)"],
             ["ta.py", "Regional TA: enrolment, A-2/A-3/A-5, dual records, caches"],
             ["federation.py", "Root TA: links, trust, escrow, TID sync, revocation"],
             ["loadbalancer.py", "Health monitor and load-balancing score"],
             ["system.py", "Facade: topology, enrolment, authentication, recovery"],
             ["channel.py", "ASCON data channel keyed by the session key"],
             ["simulation.py", "Discrete-event network simulator"],
             ["attacks.py", "Executable attack scenarios"]],
            [3.6, 11.4])
    R.h2("4.7 Evaluation methodology")
    R.p(
        "Two complementary methods are used. **Direct measurement** times every primitive and "
        "every protocol step on the real code, and counts operations with an instrumented meter. "
        "**Discrete-event simulation** executes the real protocol for every request inside a "
        "simulated network. Each link adds latency (10 ms in-region, 25 ms cross-region, 8 ms "
        "backhaul) plus Gaussian jitter (σ = 2 ms) and may drop messages. Each RTA and UAV is a "
        "first-in-first-out server whose service time is the CPU time actually measured for that "
        "step, so queueing grows out of real costs. An RTA queue holds at most 200 requests, and "
        "an overloaded RTA answers 'busy' so the vehicle can retry elsewhere. Timestamps are "
        "checked against simulated time, including queueing delay. Federation synchronisation "
        "runs asynchronously, and its CPU time is recorded separately. The baseline 'SELAP' is "
        "the same code with a single TA, in which case no federation traffic is generated.")

    # ======================================================= results
    R.h1("5. Results and Discussion")
    R.h2("5.1 Experimental platform")
    R.p(
        f"All experiments ran on {env.get('cpu_name') or env['processor']} under "
        f"{env['platform']} with "
        f"Python {env['python']}. Absolute times depend on this machine; message sizes, "
        "operation counts and security outcomes do not. Where energy is reported, it is "
        f"estimated as E = P·t with the {power} W full-load power that the SELAP authors measured "
        "for a Raspberry Pi 5 [21]. These energy values are therefore an estimate, not a "
        "measurement on embedded hardware.")
    R.h2("5.2 Cost of cryptographic primitives")
    prim = e1["primitives"]
    R.table(f"Execution time of primitives ({e1['runs']} runs each)",
            ["Primitive", "Mean (ms)", "Std. dev. (ms)", "Median (ms)"],
            [[k, f(v["mean"], 4), f(v["sd"], 4), f(v["median"], 4)] for k, v in prim.items()],
            [8.0, 2.3, 2.6, 2.3])
    asc = prim["Ascon-128 encryption, 64 B (Ta)"]["mean"]
    asc_pq = prim["Ascon-80pq encryption, 64 B"]["mean"]
    R.p(
        f"SHA-256 runs in native code and costs about {f(prim['SHA-256 hash (Th)']['mean'], 4)} ms, "
        f"while the pure-Python ASCON needs about {f(asc, 3)} ms to encrypt the largest SELAP "
        "payload. ASCON therefore dominates protocol cost in this prototype. A native or "
        "hardware ASCON would be one to two orders of magnitude faster, so the absolute "
        "numbers below are conservative. Ascon-80pq costs essentially the same as Ascon-128 "
        f"({f(asc_pq, 3)} ms): the two variants share the permutation and differ only in key "
        "loading. Evaluating the 896-bit PUF response is the most expensive single UAV "
        "operation, while the fuzzy extractor itself is very cheap.")
    R.h2("5.3 Computation cost, post-quantum mode and energy")
    ops = intra["ops_steady"]

    def opstr(d):
        parts = []
        for key, sym in (("hash", "T_{h}"), ("ascon", "T_{a}"), ("puf", "T_{p}"), ("fe", "T_{f}")):
            if d.get(key):
                parts.append(f"{d[key] if d[key] > 1 else ''}{sym}")
        return " + ".join(parts)

    rows = []
    for label, sc_ in (("SELAP (single TA)", sel), ("HF-SELAP intra-region", intra),
                       ("HF-SELAP cross-region", cross), ("HF-SELAP post-quantum", pq)):
        rows.append([label, f(sc_["vehicle"]["mean"], 3), f(sc_["uav"]["mean"], 3),
                     f(sc_["ta"]["mean"], 3), f(sc_["total_ms"], 3),
                     f(sc_["sync"]["mean"], 3) if sc_["sync"]["mean"] >= 0.01 else "–"])
    R.table(f"Mean computation time per authentication ({e2['_meta']['runs']} runs, ms)",
            ["Scenario", "Vehicle", "UAV", "Serving TA", "Total", "Async. sync"],
            rows, [4.6, 1.9, 1.9, 2.2, 1.9, 2.5])
    R.table("Primitive operations per authentication (counted by the instrumented meter)",
            ["Entity", "SELAP cost model [21]", "Measured (HF-SELAP)"],
            [["Vehicle", "5T_{h} + 2T_{a}", opstr(ops["vehicle"])],
             ["UAV", "5T_{h} + 2T_{a} + T_{p} + T_{f}", opstr(ops["uav"])],
             ["Serving TA", "8T_{h} + 4T_{a}", opstr(ops["ta"])],
             ["Serving TA, cross-region", "–", opstr(cross["ops_steady"]["ta"])],
             ["Federation sync (asynchronous)", "–",
              "; ".join(f"{opstr(o)} ({who.replace('ta', 'RTA').replace('root', 'Root TA')})"
                        for who, o in intra.get("ops_async_sync", {}).items())]],
            [4.5, 5.0, 5.5])
    R.figure(FIG / "fig_cost_per_entity.png",
             "Per-entity computation time of one authentication (error bars: 95 % confidence "
             "intervals).", 15.0)
    R.p(
        "The operation counts match the SELAP cost model exactly, which confirms that the "
        "implementation follows the protocol. The federation adds nothing to the vehicle or the "
        f"UAV. On the authentication path the serving TA also costs the same: "
        f"{f(intra['ta']['mean'], 3)} ms for HF-SELAP against {f(sel['ta']['mean'], 3)} ms for "
        "single-TA SELAP, a difference within run-to-run variation. In a cross-region run the TA "
        "performs one hash fewer, because the delegated record already contains PID_{U}, but "
        "the saving is too small to measure. The extra work HF-SELAP introduces is the asynchronous "
        f"identity write-through, about {f(intra['sync']['mean'], 3)} ms of combined RTA and Root "
        "TA time. It runs after Msg4 has been sent, so it does not delay the vehicle. The first "
        "cross-region request to a given UAV also pays a one-time credential fetch: "
        f"{f(cross['first_run']['ta'], 3)} ms at the TA against {f(cross['ta']['mean'], 3)} ms "
        f"once cached. The post-quantum mode changed the total by {f(pq_delta, 1)} %, in line "
        "with the small difference between the two ASCON variants in Table 5.")
    R.p(
        f"With the {power} W power model, one authentication costs about "
        f"{f(intra['energy_mJ']['vehicle'], 2)} mJ on the vehicle and "
        f"{f(intra['energy_mJ']['uav'], 2)} mJ on the UAV (estimate). Even with an unoptimised "
        "Python ASCON, a UAV battery of a few tens of watt-hours could fund millions of "
        "authentications, so security does not limit flight time.")
    R.h2("5.4 Communication overhead")
    R.figure(FIG / "fig_comm_overhead.png",
             "Air-interface bits per authentication. Earlier schemes as reported in [21]; "
             "HF-SELAP measured from serialised messages.", 15.0)
    sc3 = e3["scenarios"]
    R.table("Measured traffic per authentication (bits)",
            ["Scenario", "Air interface", "Backhaul (wired)", "Backhaul messages"],
            [[k, v["air_total"], v["backhaul_total"],
              ", ".join(f"{n} ×{d['messages']}" for n, d in v["backhaul"].items())]
             for k, v in sc3.items()],
            [5.4, 2.2, 2.6, 4.8])
    cp = e3["control_plane"]
    air = sc3["Intra-region (home RTA serves)"]["air_total"]
    ecc = [b for n, b in e3["reported_air_bits"].items() if not n.startswith("SELAP")]
    red_lo, red_hi = 100 * (1 - air / min(ecc)), 100 * (1 - air / max(ecc))
    sync_bits = sc3["Intra-region (home RTA serves)"]["backhaul_total"]
    R.p(
        "On the radio links, the costly and shared resource in a disaster zone, HF-SELAP sends "
        f"exactly the same {air} bits as SELAP in every scenario. That is {f(red_lo, 0)}–"
        f"{f(red_hi, 0)} % less than the "
        "four elliptic-curve schemes compared in [21]. The federation's traffic stays on the "
        f"wired backhaul. A routine authentication adds one {sync_bits}-bit identity-sync "
        "message. A "
        "cross-region or fail-over authentication additionally fetches the missing credential "
        "once, and later requests hit the cache. The remaining control-plane traffic is small: "
        f"one heartbeat is {cp['heartbeat_bits']} bits per RTA every 500 ms, a federation-wide "
        f"revocation costs {cp['revocation_broadcast']['revoke']['bits']} bits for three RTAs, "
        f"and enrolment deposits cost {cp['deposit_vehicle']['deposit_vehicle']['bits']} bits per "
        f"vehicle and {cp['deposit_uav']['deposit_uav']['bits']} bits per UAV.")
    R.h2("5.5 Storage cost")
    stg = e3["storage_bits"]
    R.table("Long-term storage (bits)", ["Item", "HF-SELAP (measured)", "SELAP (reported [21])"],
            [["Vehicle smart card", stg["Vehicle smart card"], 768],
             ["UAV smart card", stg["UAV smart card"], 656],
             ["Regional TA, per own vehicle",
              stg["Regional TA, per own vehicle <TID_o,TID_c,N_VR2,M_VR1>"], "–"],
             ["Regional TA, per own UAV", stg["Regional TA, per own UAV <ID_U,M_UR1,C_U>"], "–"],
             ["Regional TA, per cached foreign vehicle",
              stg["Regional TA, per cached foreign vehicle <TID_o,TID_c,N_VR2,PID_V>"], "–"],
             ["Root TA escrow, per vehicle", stg["Root TA escrow, per vehicle (sealed)"], "–"],
             ["Root TA escrow, per UAV", stg["Root TA escrow, per UAV (sealed)"], "–"]],
            [7.0, 4.0, 4.0])
    R.p(
        "The vehicle card matches SELAP's 768 bits exactly. The UAV card is larger because this "
        "implementation uses a concrete repetition-code fuzzy extractor, whose helper data is "
        "896 bits instead of the 144 bits assumed in [21]. A BCH or polar code would shrink the "
        "helper data at the cost of a more complex decoder. Federation storage stays on servers: "
        "about one kilobit of escrow per entity at the Root TA, and a cached record only for "
        "foreign entities an RTA has actually served.")
    R.h2("5.6 Scalability and load balancing")
    R.figure(FIG / "fig_scalability_success.png",
             "Authentication success rate versus offered load when 70 % of requests come from "
             f"Region A (mean of {e5.get('repeats', 1)} independent runs per point).", 15.0)
    R.figure(FIG / "fig_scalability_latency.png",
             "95th-percentile end-to-end latency of successful authentications versus offered "
             "load (log scale).", 15.0)
    rows = []
    for name in sc_names:
        p_ = at_rate(name, top_rate)
        cap_ = capacity(name)
        rows.append([name, f"≥ {cap_}" if cap_ == top_rate else f"{cap_}", f(100 * p_["success_rate"], 1),
                     f(p_["mean_latency_ms"], 1), f(p_["p95_latency_ms"], 1),
                     f(p_["jain_fairness"], 3)])
    R.table(f"Scalability summary (capacity = highest tested load with ≥ 99 % success; other "
            f"columns at {top_rate} requests/s)",
            ["Deployment", "Capacity (req/s)", "Success (%)", "Mean latency (ms)",
             "p95 latency (ms)", "Jain fairness"],
            rows, [5.0, 2.0, 1.8, 2.1, 2.1, 2.0])
    R.p(
        "A single TA becomes the bottleneck as soon as the offered load exceeds its service "
        "capacity. Its queue fills, requests wait past their timeouts or are refused, and "
        f"success falls to {f(100 * sel_top['success_rate'], 1)} % at {top_rate} requests/s. "
        "Adding RTAs without load balancing helps, but only partly. The hot-spot RTA still "
        "receives 70 % of the traffic while the others sit partly idle, which shows up as a Jain "
        f"fairness index of {f(static_top['jain_fairness'], 3)} and "
        f"{f(100 * static_top['success_rate'], 1)} % success. With the load balancer, requests "
        "spill over to the less loaded RTAs once the hot-spot queue grows. With three RTAs the "
        f"federation authenticated {f(100 * lb3_top['success_rate'], 1)} % at {top_rate} "
        f"requests/s, and two balanced RTAs reached {f(100 * lb2_top['success_rate'], 1)} %. "
        "Delegated credentials make this spill-over possible: the receiving RTA fetches the "
        "foreign record once and caches it, so the radio exchange stays unchanged.")
    R.h2("5.7 Fault tolerance")
    R.figure(FIG / "fig_fault_success.png",
             f"Share of requests authenticated within {int(e6['deadline_ms'])} ms, by request "
             f"start time; RTA-1 fails at 4 s and recovers at 8 s ({int(e6['rate'])} requests/s).",
             15.0)
    R.figure(FIG / "fig_fault_latency.png",
             "Mean latency of successful authentications around the failure (log scale).", 15.0)
    R.table("Behaviour while RTA-1 is down (requests started between 4 s and 8 s)",
            ["Deployment", "Within 1 s (%)", "Eventually (%)", "Mean latency (ms)",
             "Max latency (ms)"],
            [[k, f(v["outage_timely_pct"], 1), f(v["outage_success_pct"], 1),
              f(v["outage_mean_latency_ms"], 0) if v["outage_mean_latency_ms"] else "–",
              f(v["outage_max_latency_ms"], 0)] for k, v in fc.items()],
            [5.6, 2.3, 2.3, 2.4, 2.4])
    R.p(
        "With a single TA, every request that starts during the outage misses the one-second "
        "deadline. Some succeed only after the TA returns, seconds later, which is too late for "
        "an emergency message. Static federation protects the regions whose own RTA is alive but "
        "abandons Region A. With heartbeat fail-over, the failed RTA was detected after "
        f"{f(detect_s, 2) if detect_s is not None else '–'} s (three missed heartbeats). Requests "
        "already sent to it time out and are retried elsewhere. "
        + ("Every request of the outage window was eventually served: "
           if f_hf["outage_success_pct"] >= 99.95 else "Of the outage-window requests, ")
        +
        f"{f(f_hf['outage_timely_pct'], 1)} % within one second and "
        f"{f(f_hf['outage_success_pct'], 1)} % overall. The latency spike is limited to the "
        "detection window. When RTA-1 returns, the Root TA replays the identity updates and "
        "revocations it missed, so its vehicles authenticate normally again.")
    R.h2("5.8 High mobility and stress")
    R.figure(FIG / "fig_mobility_success.png",
             f"Authentication success versus speed on a 30 km evacuation corridor "
             f"({e7['n_vehicles']} vehicles, 1 km UAV cells, loss rising with speed).", 15.0)
    R.figure(FIG / "fig_mobility_latency.png",
             "Mean authentication latency versus vehicle speed.", 15.0)
    R.table(f"Mobility results at {top_speed} km/h",
            ["Deployment", "Offered load (req/s)", "Success (%)", "Within 1 s (%)",
             "Mean latency (ms)", "Cross-region (%)", "Desync lock-outs"],
            [[k, f(v["offered_rate_per_s"], 0), f(v["success_pct"], 2), f(v["timely_pct"], 2),
              f(v["mean_latency_ms"], 0), f(v["delegated_pct"], 0), v["desync_lockouts"]]
             for k, v in m_top.items()],
            [4.6, 1.9, 1.7, 1.8, 1.9, 1.9, 1.7])
    R.p(
        "Higher speed means more frequent cell changes (more authentications per second) and, "
        f"in our stress model, more packet loss: {f(m_top[m_names[0]]['vehicle_hop_loss_pct'], 1)} "
        f"% per vehicle hop at {top_speed} km/h. Retries keep the success rate of both SELAP "
        f"and HF-SELAP at or above "
        f"{f(math.floor(10 * min(m_top[m_names[0]]['success_pct'], m_top[m_names[1]]['success_pct'])) / 10, 1)} %, and "
        "the extra latency comes "
        "from the 1.5 s timeouts after lost messages. Because evacuating vehicles come from "
        f"everywhere, {f(m_top[m_names[1]]['delegated_pct'], 0)} % of HF-SELAP authentications "
        "were served through delegation, which shows the federation working in practice. The "
        "ablation is the most telling result. When the dual ⟨TID^{o}, TID^{c}⟩ record is "
        f"removed, every lost Msg4 strands a vehicle on an identity the TA no longer accepts: "
        f"{m_top[m_names[2]]['desync_lockouts']} lock-outs occurred at {top_speed} km/h, and "
        f"success fell to {f(m_top[m_names[2]]['success_pct'], 1)} %. With the dual record there "
        "were none. The ablation's lower mean latency in Fig. 10 is a selection effect, not a "
        "benefit: its requests that hit a lost Msg4 end in failure instead of in a slow but "
        "successful retry, so they drop out of the latency average.")
    R.h2("5.9 PUF and fuzzy-extractor reliability")
    R.figure(FIG / "fig_puf_reliability.png",
             "Key-reproduction failure per PUF read versus bit-error rate for repetition "
             f"factors 3–9 ({e8['trials_per_point']} trials per point).", 15.0)
    R.figure(FIG / "fig_puf_hamming.png",
             "Intra-device versus inter-device Hamming distance of 896-bit responses.", 15.0)
    R.table("End-to-end UAV authentication failure (%) with 1 or 3 permitted PUF reads",
            ["Noise / reads", "Failure (%)"],
            [[_pretty_noise(k), f(v, 2)] for k, v in e8["e2e_failure_pct"].items()], [6.0, 3.0])
    R.p(
        f"The responses are well separated. Re-reads of one chip differ in "
        f"{f(100 * e8['intra_hd']['mean'], 1)} % of bits on average, different chips in "
        f"{f(100 * e8['inter_hd']['mean'], 1)} %, and the bit uniformity is "
        f"{f(100 * e8['uniformity'], 1)} %. A clone therefore misses the key by a wide margin, "
        "while the genuine UAV stays well inside the correction radius. At the default 3 % noise, "
        f"a single read with repetition 7 failed in {f(100 * rep7[noise_idx], 2)} % of trials. "
        "Allowing up to three reads lowers end-to-end failure from "
        f"{f(e8['e2e_failure_pct']['noise=0.09, reads=1'], 2)} % to "
        f"{f(e8['e2e_failure_pct']['noise=0.09, reads=3'], 2)} % even at 9 % noise. Shorter "
        f"codes are inadequate: at 4 % noise one read fails in "
        f"{f(100 * e8['curves']['3']['empirical'][i4], 1)} % of trials with repetition 3 and "
        f"{f(100 * e8['curves']['5']['empirical'][i4], 1)} % with repetition 5, against "
        f"{f(100 * e8['curves']['7']['empirical'][i4], 1)} % with repetition 7, which is why 7 "
        "is the default. Repetition 9 is more robust still, but makes the helper data "
        "proportionally larger.")
    R.h2("5.10 Revocation and recovery")
    R.table("Revocation and recovery cost versus re-registering the whole network",
            ["Enrolled vehicles N", "Revoke one (ms / bits)", "Re-enrol one (ms / bits)",
             "Full reset (ms / bits)", "Revoked rejected by all RTAs"],
            [[r_["N"], f"{f(r_['revoke_ms'], 2)} / {r_['revoke_bits']}",
              f"{f(r_['reenrol_ms'], 2)} / {r_['reenrol_bits']}",
              f"{f(r_['full_reset_ms'], 0)} / {r_['full_reset_bits']:,}",
              "yes" if r_["revoked_rejected_by_all_rtas"] else "no"] for r_ in rev_rows],
            [2.8, 3.2, 3.2, 3.6, 2.6])
    R.p(
        "Revocation and recovery costs do not depend on the network size. Revoking an entity is "
        "one message per RTA, and recovering it is one enrolment. Without a recovery protocol, "
        f"replacing compromised credentials safely would mean re-enrolling all {rev_big['N']} "
        f"vehicles: {f(rev_big['full_reset_ms'], 0)} ms of computation and "
        f"{rev_big['full_reset_bits']:,} bits at enrolment alone, before counting the physical "
        "re-issue of smart cards. In every run, the revoked entity was rejected by every RTA, "
        "including RTAs that had cached its credentials earlier, and the re-enrolled entity "
        "authenticated successfully.")
    R.h2("5.11 Security evaluation")
    R.p(
        f"Table {R.tab_no + 1} lists the executable attack scenarios. Each scenario builds a "
        "fresh federation, mounts the attack through the message tap or by direct calls, and "
        "records the protocol's reaction.")
    R.table(f"Attack scenarios ({blocked}/{total} blocked)",
            ["Attack", "Target", "Defence that stopped it", "Result"],
            [[s_["attack"], s_["target"], s_["defence"], "Blocked" if s_["blocked"] else "NOT blocked"]
             for s_ in e10["scenarios"]],
            [5.6, 2.2, 5.2, 2.0], font=8.5)
    abl = e10["ablation_without_dual_record"]
    R.p(
        f"All {total} attacks were blocked. The ablation confirms that the defences are "
        f"necessary: with dual temporary-identity records disabled, the desynchronisation "
        f"attack succeeds ({abl['observed']}). Table {R.tab_no + 1} summarises the security "
        "and functional properties.")
    R.table("Security and functional properties",
            ["Property", "SELAP [21]", "HF-SELAP"],
            [["Mutual authentication and session-key agreement", "✓", "✓"],
             ["Anonymity and untraceability (rotating TID)", "✓", "✓"],
             ["Replay, MitM, impersonation, forgery resistance", "✓", "✓"],
             ["Smart-card loss resistance", "✓", "✓ + lockout"],
             ["Desynchronisation resistance", "✓", "✓ (federation-consistent)"],
             ["Physical security of UAVs (PUF), noise tolerance", "✓", "✓ + re-read"],
             ["Multiple trusted authorities / cross-region service", "✗", "✓"],
             ["Load balancing", "✗", "✓"],
             ["TA fault tolerance", "✗", "✓"],
             ["Revocation of compromised entities", "✗", "✓"],
             ["Recovery / re-enrolment without reset", "✗", "✓"],
             ["Post-quantum key length option", "✗", "✓ (Ascon-80pq)"]],
            [8.6, 2.6, 3.8])
    R.p(
        "**Post-quantum considerations.** SELAP and HF-SELAP use no public-key cryptography, so "
        "Shor's algorithm, which breaks RSA and elliptic-curve schemes, does not apply. The "
        "remaining quantum threat is Grover's search, which roughly halves the effective "
        "length of symmetric keys. Ascon-128 offers about 64-bit security against quantum key "
        "search, and the Ascon-80pq mode raises this to about 80 bits. SHA-256 keeps roughly "
        "128-bit preimage resistance. The migration changed neither message sizes nor storage "
        f"and moved total computation by {f(pq_delta, 1)} %. A complete post-quantum design "
        "would also need quantum-safe enrolment if public-key bootstrapping were ever "
        "introduced (for example ML-KEM); the present symmetric design avoids that need.")
    R.h2("5.12 Discussion and limitations")
    R.p(
        "The results show that the federation layer adds availability, scalability and life-cycle "
        "security without touching what makes SELAP attractive: the radio messages, the "
        "vehicle's work and the UAV's work are unchanged. The costs fall on the wired backhaul "
        "and on servers, which are the resources that can most easily be provisioned. Several "
        "limitations remain. The prototype runs in one process, with simulated links and a "
        "simulated PUF, so the absolute timings are those of a Python implementation on a "
        "desktop CPU. As in SELAP, TAs are fully trusted and can compute session keys, and "
        "escrowing pseudonymous credentials at the Root TA widens that trusted base. The "
        "speed-dependent loss model is an assumption, and real UAV-to-vehicle channels should "
        "be measured. Clock synchronisation within ΔT is assumed rather than enforced. The "
        "repetition-code fuzzy extractor makes UAV storage larger than SELAP's estimate.")

    # ----------------------------------------------------- conclusion
    R.h1("6. Conclusion")
    R.p(
        "This project designed, implemented and evaluated HF-SELAP, which extends the lightweight "
        "SELAP authentication protocol for UAV-assisted VANETs from a single trusted authority to "
        "a hierarchical federation of Regional TAs under a Root TA. The SELAP exchange is "
        "preserved exactly: four ASCON-protected messages totalling 2432 bits, the same "
        "operation counts on vehicles and UAVs, and PUF-based UAV identity. Around it, HF-SELAP "
        "adds delegated cross-region authentication, load balancing, heartbeat fail-over with "
        "resynchronisation, a federated revocation registry, recovery by re-enrolment and an "
        f"Ascon-80pq post-quantum mode. In the measurements, the vehicle needed "
        f"{f(intra['vehicle']['mean'], 3)} ms and the UAV {f(intra['uav']['mean'], 3)} ms of "
        f"computation per authentication. Three balanced RTAs sustained "
        f"{f(100 * lb3_top['success_rate'], 1)} % success at {top_rate} requests/s where a single "
        f"TA managed {f(100 * sel_top['success_rate'], 1)} %. During a TA outage, "
        f"{f(f_hf['outage_timely_pct'], 1)} % of requests were still served within one second. "
        f"All {total} attack scenarios were blocked. Future work includes a native and "
        "hardware-accelerated implementation on embedded UAV platforms, field trials with real "
        "5G/C-V2X radios and hardware PUFs, threshold or multi-party techniques so that no single "
        "TA can derive session keys, a compact fuzzy extractor based on BCH or polar codes, and "
        "formal verification of the federation messages with tools such as ProVerif.")

    # ----------------------------------------------------- references
    R.h1("References")
    refs = [
        "K. S. Nwizege, M. Bottero, S. Mmeah, and E. D. Nwiwure, “Vehicles-to-infrastructure communication safety messaging in DSRC,” Procedia Computer Science, vol. 34, pp. 559–564, 2014.",
        "M.-Y. Hsieh, H.-Y. Lin, C.-F. Lai, and K.-C. Li, “Secure protocols for data propagation and group communication in vehicular networks,” EURASIP Journal on Wireless Communications and Networking, vol. 2011, Art. no. 167, 2011.",
        "J. Cui, X. Liu, H. Zhong, J. Zhang, L. Wei, I. Bolodurina, and D. He, “A practical and provably secure authentication and key agreement scheme for UAV-assisted VANETs for emergency rescue,” IEEE Transactions on Network Science and Engineering, vol. 11, no. 2, pp. 1454–1468, 2024.",
        "S. A. Alfadhli, S. Lu, K. Chen, and M. Sebai, “MFSPV: A multi-factor secured and lightweight privacy-preserving authentication scheme for VANETs,” IEEE Access, vol. 8, pp. 147602–147616, 2020.",
        "A. Aghabagherloo, M. Delavar, J. Mohajeri, M. Salmasizadeh, and B. Preneel, “An efficient and physically secure privacy-preserving authentication scheme for vehicular ad-hoc networks (VANETs),” IEEE Transactions on Intelligent Transportation Systems, vol. 23, no. 12, pp. 25298–25313, 2022.",
        "R. Aissaoui, J.-C. Deneuville, C. Guerber, and A. Pirovano, “A survey on cryptographic methods to secure communications for UAV traffic management,” Vehicular Communications, vol. 44, Art. no. 100661, 2023.",
        "T. W. Chim, S. M. Yiu, L. C. K. Hui, and V. O. K. Li, “MLAS: Multiple level authentication scheme for VANETs,” Ad Hoc Networks, vol. 10, no. 7, pp. 1445–1456, 2012.",
        "S. K. A. Theodore, K. R. Gandhi, and V. Palanisamy, “A novel lightweight authentication and privacy-preserving protocol for vehicular ad hoc networks,” Complex & Intelligent Systems, vol. 9, no. 3, pp. 2981–2991, 2023.",
        "D. R. Sona, K. Bagadi, V. Annepu, O. O. Oyerinde, M. Manikanta, K. A. Gangireddy, S. Dintakurthi, and K. S. K. Reddy, “Optimized UAV-based relay algorithm for enhanced emergency wireless coverage in disaster areas,” Engineering Reports, Art. no. e70295, 2025.",
        "P. Thorncharoensri, W. Susilo, and Y. Chow, “Secure and efficient communication in VANETs using level-based access control,” Security and Communication Networks, vol. 2022, Art. no. 8736531, 2022.",
        "T. Gao, X. Deng, N. Guo, and X. Wang, “An anonymous authentication scheme based on PMIPv6 for VANETs,” IEEE Access, vol. 6, pp. 14686–14698, 2018.",
        "M. Fogue, F. J. Martínez, P. Garrido, M. Fiore, C.-F. Chiasserini, C. Casetti, J.-C. Cano, C. T. Calafate, and P. Manzoni, “Securing warning message dissemination in VANETs using cooperative neighbor position verification,” IEEE Transactions on Vehicular Technology, vol. 64, no. 6, pp. 2538–2550, 2015.",
        "M. A. Shawky, M. Usman, M. A. Imran, Q. H. Abbasi, S. Ansari, and A. Taha, “Adaptive chaotic map-based key extraction for efficient cross-layer authentication in VANETs,” IET Intelligent Transport Systems, vol. 17, 2023.",
        "S. A. Jan, N. U. Amin, M. Othman, M. Ali, A. I. Umar, and A. Basir, “A survey on privacy-preserving authentication schemes in VANETs: Attacks, challenges and open issues,” Telecommunication Systems, vol. 84, pp. 99–136, 2023.",
        "T. Jing, Y. Pei, B. Zhang, C. Hu, Y. Huo, H. Li, and Y. Lu, “An efficient anonymous batch authentication scheme based on priority and cooperation for VANETs,” EURASIP Journal on Wireless Communications and Networking, vol. 2018, Art. no. 294, 2018.",
        "N. P. Sharvari, D. Das, J. Bapat, and D. Das, “Connectivity and collision constrained opportunistic routing for emergency communication using UAV,” Computer Networks, vol. 227, Art. no. 109714, 2023.",
        "M. Matracia, N. Saeed, M. A. Kishk, and M.-S. Alouini, “Post-disaster communications: Enabling technologies, architectures, and open challenges,” IEEE Open Journal of the Communications Society, vol. 3, pp. 1177–1205, 2022.",
        "Y. Lei, L. Zeng, Y.-X. Li, M.-X. Wang, and H. Qin, “A lightweight authentication protocol for UAV networks based on security and computational resource optimization,” IEEE Internet of Things Journal, vol. 8, no. 18, pp. 14096–14109, 2021.",
        "P. Wang, C.-M. Chen, S. Kumari, M. Shojafar, R. Tafazolli, and Y.-N. Liu, “HDMA: Hybrid D2D message authentication scheme for 5G-enabled VANETs,” IEEE Transactions on Intelligent Transportation Systems, vol. 22, no. 8, pp. 5071–5085, 2021.",
        "H. Tan and I. Chung, “Secure authentication and key management with blockchain in VANETs,” IEEE Access, vol. 8, pp. 171414–171428, 2020.",
        "M. Wu, X. Ai, A. Badshah, S. Tu, Z. Ning, H. Alfuhaid, M. Waqas, and Z. Halim, “SELAP: A security-enhanced lightweight authentication protocol for UAV-assisted VANETs in emergency scenarios,” Computer Networks, vol. 287, Art. no. 112523, 2026.",
        "C. Dobraunig, M. Eichlseder, F. Mendel, and M. Schläffer, “Ascon v1.2: Lightweight authenticated encryption and hashing,” Journal of Cryptology, vol. 34, no. 3, Art. no. 33, 2021.",
    ]
    for i, ref in enumerate(refs, 1):
        para = doc.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        para.paragraph_format.left_indent = Cm(0.9)
        para.paragraph_format.first_line_indent = Cm(-0.9)
        para.paragraph_format.space_after = Pt(3)
        run = para.add_run(f"[{i}]\t{ref}")
        run.font.size = Pt(9.5)

    try:
        doc.save(OUT)
    except PermissionError:
        sys.exit(f"Cannot write {OUT.name}: it is probably open in Word. "
                 "Close it and run this script again.")
    print(f"written {OUT}  ({R.fig_no} figures, {R.tab_no} tables)")


if __name__ == "__main__":
    build()
