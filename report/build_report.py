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


REFERENCES = [
    'K. S. Nwizege, M. Bottero, S. Mmeah, and E. D. Nwiwure, “Vehicles-to-infrastructure communication safety messaging in DSRC,” Procedia Computer Science, vol. 34, pp. 559–564, 2014.',
    'M.-Y. Hsieh, H.-Y. Lin, C.-F. Lai, and K.-C. Li, “Secure protocols for data propagation and group communication in vehicular networks,” EURASIP Journal on Wireless Communications and Networking, vol. 2011, Art. no. 167, 2011.',
    'J. Cui, X. Liu, H. Zhong, J. Zhang, L. Wei, I. Bolodurina, and D. He, “A practical and provably secure authentication and key agreement scheme for UAV-assisted VANETs for emergency rescue,” IEEE Transactions on Network Science and Engineering, vol. 11, no. 2, pp. 1454–1468, 2024.',
    'S. A. Alfadhli, S. Lu, K. Chen, and M. Sebai, “MFSPV: A multi-factor secured and lightweight privacy-preserving authentication scheme for VANETs,” IEEE Access, vol. 8, pp. 147602–147616, 2020.',
    'A. Aghabagherloo, M. Delavar, J. Mohajeri, M. Salmasizadeh, and B. Preneel, “An efficient and physically secure privacy-preserving authentication scheme for vehicular ad-hoc networks (VANETs),” IEEE Transactions on Intelligent Transportation Systems, vol. 23, no. 12, pp. 25298–25313, 2022.',
    'R. Aissaoui, J.-C. Deneuville, C. Guerber, and A. Pirovano, “A survey on cryptographic methods to secure communications for UAV traffic management,” Vehicular Communications, vol. 44, Art. no. 100661, 2023.',
    'T. W. Chim, S. M. Yiu, L. C. K. Hui, and V. O. K. Li, “MLAS: Multiple level authentication scheme for VANETs,” Ad Hoc Networks, vol. 10, no. 7, pp. 1445–1456, 2012.',
    'S. K. A. Theodore, K. R. Gandhi, and V. Palanisamy, “A novel lightweight authentication and privacy-preserving protocol for vehicular ad hoc networks,” Complex & Intelligent Systems, vol. 9, no. 3, pp. 2981–2991, 2023.',
    'D. R. Sona, K. Bagadi, V. Annepu, O. O. Oyerinde, M. Manikanta, K. A. Gangireddy, S. Dintakurthi, and K. S. K. Reddy, “Optimized UAV-based relay algorithm for enhanced emergency wireless coverage in disaster areas,” Engineering Reports, Art. no. e70295, 2025.',
    'P. Thorncharoensri, W. Susilo, and Y. Chow, “Secure and efficient communication in VANETs using level-based access control,” Security and Communication Networks, vol. 2022, Art. no. 8736531, 2022.',
    'T. Gao, X. Deng, N. Guo, and X. Wang, “An anonymous authentication scheme based on PMIPv6 for VANETs,” IEEE Access, vol. 6, pp. 14686–14698, 2018.',
    'M. Fogue, F. J. Martínez, P. Garrido, M. Fiore, C.-F. Chiasserini, C. Casetti, J.-C. Cano, C. T. Calafate, and P. Manzoni, “Securing warning message dissemination in VANETs using cooperative neighbor position verification,” IEEE Transactions on Vehicular Technology, vol. 64, no. 6, pp. 2538–2550, 2015.',
    'M. A. Shawky, M. Usman, M. A. Imran, Q. H. Abbasi, S. Ansari, and A. Taha, “Adaptive chaotic map-based key extraction for efficient cross-layer authentication in VANETs,” IET Intelligent Transport Systems, vol. 17, 2023.',
    'S. A. Jan, N. U. Amin, M. Othman, M. Ali, A. I. Umar, and A. Basir, “A survey on privacy-preserving authentication schemes in VANETs: Attacks, challenges and open issues,” Telecommunication Systems, vol. 84, pp. 99–136, 2023.',
    'T. Jing, Y. Pei, B. Zhang, C. Hu, Y. Huo, H. Li, and Y. Lu, “An efficient anonymous batch authentication scheme based on priority and cooperation for VANETs,” EURASIP Journal on Wireless Communications and Networking, vol. 2018, Art. no. 294, 2018.',
    'N. P. Sharvari, D. Das, J. Bapat, and D. Das, “Connectivity and collision constrained opportunistic routing for emergency communication using UAV,” Computer Networks, vol. 227, Art. no. 109714, 2023.',
    'M. Matracia, N. Saeed, M. A. Kishk, and M.-S. Alouini, “Post-disaster communications: Enabling technologies, architectures, and open challenges,” IEEE Open Journal of the Communications Society, vol. 3, pp. 1177–1205, 2022.',
    'Y. Lei, L. Zeng, Y.-X. Li, M.-X. Wang, and H. Qin, “A lightweight authentication protocol for UAV networks based on security and computational resource optimization,” IEEE Internet of Things Journal, vol. 8, no. 18, pp. 14096–14109, 2021.',
    'P. Wang, C.-M. Chen, S. Kumari, M. Shojafar, R. Tafazolli, and Y.-N. Liu, “HDMA: Hybrid D2D message authentication scheme for 5G-enabled VANETs,” IEEE Transactions on Intelligent Transportation Systems, vol. 22, no. 8, pp. 5071–5085, 2021.',
    'H. Tan and I. Chung, “Secure authentication and key management with blockchain in VANETs,” IEEE Access, vol. 8, pp. 171414–171428, 2020.',
    'M. Wu, X. Ai, A. Badshah, S. Tu, Z. Ning, H. Alfuhaid, M. Waqas, and Z. Halim, “SELAP: A security-enhanced lightweight authentication protocol for UAV-assisted VANETs in emergency scenarios,” Computer Networks, vol. 287, Art. no. 112523, 2026.',
    'C. Dobraunig, M. Eichlseder, F. Mendel, and M. Schläffer, “Ascon v1.2: Lightweight authenticated encryption and hashing,” Journal of Cryptology, vol. 34, no. 3, Art. no. 33, 2021.',
    'S. S. Al-Riyami and K. G. Paterson, “Certificateless public key cryptography,” in Advances in Cryptology – ASIACRYPT 2003, Lecture Notes in Computer Science, vol. 2894. Berlin, Germany: Springer, 2003, pp. 452–473.',
    'National Institute of Standards and Technology, “Digital Signature Standard (DSS),” Federal Information Processing Standards Publication FIPS 186-5, Feb. 2023.',
    'National Institute of Standards and Technology, “Recommendations for discrete logarithm-based cryptography: Elliptic curve domain parameters,” NIST Special Publication 800-186, Feb. 2023.',
]


def f(x, d=2):
    return f"{x:,.{d}f}"


def count_tests() -> int:
    import unittest
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return unittest.defaultTestLoader.discover(str(ROOT / "tests"),
                                               top_level_dir=str(ROOT)).countTestCases()


# ======================================================================
# content
# ======================================================================
def build():
    diagrams.architecture()
    diagrams.message_flow()
    e1, e2, e3 = load("e1_primitives"), load("e2_cost"), load("e3_overhead")
    e5, e6, e7 = load("e5_scalability"), load("e6_fault"), load("e7_mobility")
    e8, e9, e10 = load("e8_cl"), load("e9_revocation"), load("e10_security")
    env = load("environment")
    n_tests = count_tests()

    base = e2["Single TA (no federation)"]
    intra = e2["HF-SELAP intra-region"]
    cross = e2["HF-SELAP cross-region (delegated)"]
    pq = e2["HF-SELAP post-quantum (Ascon-80pq)"]
    pq_delta = 100.0 * (pq["total_ms"] - intra["total_ms"]) / intra["total_ms"]
    power = e2["_meta"]["power_model_W"]

    sc = e5["configs"]
    sc_names = list(sc)
    rates = e5["rates"]
    top_rate = rates[-1]

    def at_rate(name, rate):
        return next(p for p in sc[name] if p["offered_rate"] == rate)

    def capacity(name, thr=0.99):
        ok = [p["offered_rate"] for p in sc[name] if p["success_rate"] >= thr]
        return max(ok) if ok else 0

    base_top = at_rate(sc_names[0], top_rate)
    static_top = at_rate(sc_names[1], top_rate)
    lb2_top = at_rate(sc_names[2], top_rate)
    lb3_top = at_rate(sc_names[3], top_rate)
    cap_base, cap_lb3 = capacity(sc_names[0]), capacity(sc_names[3])

    fc = e6["configs"]
    f_base, f_static, f_hf = (fc[k] for k in fc)
    detect_s = (f_hf["detections_ms"][0][1] - e6["fail_at_ms"]) / 1000.0 if f_hf["detections_ms"] else None

    mob = e7["configs"]
    m_names = list(mob)
    m_top = {k: v[-1] for k, v in mob.items()}
    top_speed = e7["speeds"][-1]

    rev_rows = e9["rows"]
    rev_big = rev_rows[-1]
    blocked, total = e10["blocked"], e10["total"]

    sc3 = e3["scenarios"]
    air = sc3["Intra-region (home RTA serves)"]["air_total"]
    selap_air = e3["reported_air_bits"]["SELAP (base paper)"]
    ecc = {n: b for n, b in e3["reported_air_bits"].items() if not n.startswith("SELAP")}

    comp = e8["composition_ms"]

    def cl_share(who):
        c = comp[who]
        return 100.0 * c["certificateless"] / (c["hash"] + c["ascon"] + c["certificateless"])

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
        "trusted authority (TA), it ties UAV identity to PUF hardware whose noisy responses need a "
        "fuzzy extractor and helper data, and it does not handle overload, authority failure, "
        "compromised devices or the move to quantum-resistant parameters. This work proposes and "
        "implements **HF-SELAP**, a hierarchical federated extension. HF-SELAP keeps SELAP's "
        "four-message ASCON exchange but replaces the PUF and fuzzy extractor with pairing-free "
        "certificateless public-key authentication: every vehicle and UAV combines a secret value "
        "of its own with a partial private key from a key generation centre and signs its "
        "protocol message, so no certificates are needed and the key generation centre never "
        "learns a complete private key. Authentication is spread over several Regional TAs "
        "coordinated by a Root/Federation TA, with score-based TA selection and load balancing, "
        "heartbeat-based fail-over, federated trust management, a revocation registry, identity "
        "refresh, recovery by re-enrolment and an Ascon-80pq post-quantum mode. The complete system "
        "was implemented in Python. That includes a from-scratch ASCON verified against the "
        "reference implementation, the certificateless scheme on the NIST P-256 curve, and a "
        "discrete-event network simulator. "
        f"Measured results show {f(intra['vehicle']['mean'], 3)} ms of computation on the vehicle "
        f"and {f(intra['uav']['mean'], 3)} ms on the UAV per authentication, with {air} bits on "
        f"the air interface. Under a 70 % hot-spot load of {top_rate} requests/s, three "
        f"load-balanced Regional TAs authenticated {f(100 * lb3_top['success_rate'], 1)} % of "
        f"requests, against {f(100 * base_top['success_rate'], 1)} % for a single TA. While a "
        f"Regional TA was down, {f(f_hf['outage_timely_pct'], 1)} % of requests were still "
        f"served within one second, against {f(f_base['outage_timely_pct'], 1)} % without "
        f"federation. All {total} implemented attack scenarios were blocked, including "
        "public-key replacement and malicious key-generation-centre attacks, and the "
        f"post-quantum mode changed the total computation by {f(pq_delta, 1)} %.")
    kw = doc.add_paragraph()
    kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    R.rich(kw, "**Keywords:** UAV-assisted VANET, Lightweight authentication, Certificateless "
               "cryptography, ASCON, Federated trust management, Disaster communication")

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
        "that need many elliptic-curve or pairing operations per session are poorly matched to "
        "the task [6], [14]. Finally, people expect their identity and movements to stay private, "
        "even during an emergency.")
    R.p(
        "SELAP, the base protocol of this project [21], answers these concerns with a careful "
        "combination of symmetric primitives. All protocol messages are protected by the "
        "lightweight AEAD scheme ASCON [22]. UAV identities are tied to PUF responses that are "
        "stabilised by a fuzzy extractor. A pair of old and current temporary identities kept "
        "at the TA prevents desynchronisation. The result is a four-message exchange of only "
        f"{selap_air} bits. The SELAP authors themselves point out the limits of the design: "
        "everything depends on one trusted authority, robustness under heavy load and high "
        "mobility has not been examined, the PUF and fuzzy extractor add hardware dependence and "
        "management complexity, compromised entities cannot be revoked and rehabilitated, and "
        "migration to post-quantum primitives is left open.")
    R.p("This project turns those open points into a working system. Its contributions are:")
    R.bullets([
        "**A hierarchical federated architecture (HF-SELAP).** Regional TAs run the "
        "authentication exchange for their regions. A Root/Federation TA keeps inter-TA trust, a "
        "sealed credential escrow and a federated identity directory, so any trusted Regional TA "
        "can serve a foreign vehicle or UAV without new radio messages.",
        "**Certificateless authentication instead of PUFs.** Each entity's private key "
        "SK_{E} = x_{E} + D_{E} combines a secret value chosen by the entity with a partial "
        "private key issued by a key generation centre (KGC) hosted by the Root TA [23]. The "
        "Regional TA verifies signatures with the registered public key. No certificates, special "
        "hardware or helper data are needed, and the KGC never knows a complete private key.",
        "**Availability mechanisms.** Regional TAs are chosen by a score that combines load, "
        "availability, reliability and communication delay. Inter-TA trust evolves with observed "
        "service, a heartbeat monitor detects failed TAs and fails over to healthy ones, and "
        "recovered TAs are resynchronised automatically.",
        "**Life-cycle security.** A versioned, federation-wide revocation registry is pushed to "
        "every Regional TA. Pseudonyms are refreshed after every session. Recovery by "
        "re-enrolment issues fresh credentials and a fresh key pair to one entity without a "
        "network reset. An optional post-quantum mode switches the symmetric layer to Ascon-80pq "
        "with 160-bit keys.",
        "**A complete, tested implementation and evaluation.** The evaluation covers computation, "
        "communication, storage, energy, scalability, delay decomposition, load imbalance, fault "
        f"tolerance, mobility, certificateless key management and {total} executable attack "
        "scenarios, all reproducible from the published scripts.",
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
    R.h2("2.3 Hardware-rooted and certificateless authentication")
    R.p(
        "Alfadhli et al. [4] proposed MFSPV, a multi-factor scheme in which PUFs and one-time "
        "dynamic pseudonyms protect V2V and V2I exchanges against cloning, impersonation and "
        "replay. The design assumes dependable PUF hardware and trusted regional certificate "
        "authorities. Aghabagherloo et al. [5] combined the advantages of RSU-aided and "
        "tamper-resistant-device-aided conditional privacy-preserving authentication. Their scheme "
        "keeps working, and even detects tampering, when an on-board unit is physically "
        "compromised. These works show the value of binding identity to hardware, which SELAP "
        "adopts for UAVs. Hardware binding has a price, however: noisy PUF responses need a fuzzy "
        "extractor and stored helper data, enrolment needs the physical device, and a damaged "
        "module cannot be re-provisioned remotely.")
    R.p(
        "Certificateless public-key cryptography, introduced by Al-Riyami and Paterson [23], "
        "offers a software alternative. A key generation centre issues only a partial private "
        "key, and each user completes it with a secret value of its own. This removes the "
        "certificate management of a conventional public-key infrastructure and the key escrow "
        "of identity-based cryptography, because no single party knows a user's full key. The "
        "original constructions use bilinear pairings; pairing-free variants built from ordinary "
        "elliptic-curve operations keep the same structure at a much lower cost, which is the "
        "approach HF-SELAP follows. Tan and Chung [20] show that certificateless authentication "
        "fits vehicular networks, although their design adds blockchain consensus.")
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
             ["[20]", "Consortium blockchain + edge + CRT", "Certificateless auth, group keys",
              "Consensus/storage overhead"]],
            [1.1, 4.6, 4.5, 4.8])
    R.h2("2.6 Research gap")
    R.p(
        "Taken together, the literature offers efficient cryptographic building blocks and "
        "capable UAV networking schemes, but they are rarely combined. SELAP [21] closes much "
        "of this gap. It brings ASCON, PUFs, a fuzzy extractor and desynchronisation-resistant "
        "identity updates into one protocol for UAV-assisted VANETs and outperforms elliptic-curve "
        "designs in cost. What remains open is the system around the protocol: a single trusted "
        "authority is both a capacity limit and a single point of failure, UAV identity depends "
        "on PUF hardware and helper data, compromised entities cannot be removed and re-admitted, "
        "behaviour under overload and high mobility is unknown, and there is no post-quantum "
        "path. HF-SELAP is designed to fill exactly these gaps. It keeps SELAP's lightweight "
        "ASCON message structure and replaces hardware-bound identity with certificateless keys.")

    # ---------------------------------------------------- architecture
    R.h1("3. Proposed System Architecture")
    R.p(
        "The architecture (Fig. 1) arranges the system in layers. Vehicles and UAVs form the "
        "access layer. Regional TAs form the authentication layer. A Root/Federation TA, which "
        "also hosts the key generation centre, forms the trust-coordination layer. A set of "
        "cross-cutting security modules and an evaluation layer complete the design.")
    R.figure(FIG / "fig_architecture.png",
             "HF-SELAP architecture: certificateless authentication at Regional TAs under a "
             "Root/Federation TA, with load balancing, fail-over and cross-cutting security "
             "modules.", 14.5)
    R.h2("3.1 Components and their roles")
    R.bullets([
        "**Vehicles / on-board units.** A vehicle requests emergency service, unlocks its smart "
        "card with its identity and password, and runs steps A-1 and A-6. The card holds the "
        "vehicle's symmetric credentials and its certificateless private key SK_{V}, so the OBU "
        "performs only hashing, two ASCON operations and one signature per session.",
        "**UAV clusters.** UAVs give coverage where ground infrastructure has failed. Each UAV "
        "holds a certificateless key pair; its smart card seals the credentials N_{UR1}, C_{U} "
        "and the private key SK_{U} under the operator's password. No special hardware is "
        "required. UAVs are grouped by region so the fleet can grow.",
        "**Regional TAs (RTAs).** Each RTA manages the vehicles and UAVs enrolled in its region "
        "and runs the TA side of the protocol (A-2, A-3, A-5). It verifies both signatures with "
        "the registered public keys and keeps SELAP's dual temporary-identity records, a replay "
        "cache, the local copy of the revocation list, and a cache of credentials delegated by "
        "the federation.",
        "**Federation / Root TA and KGC.** The Root TA authorises the RTAs and hosts the key "
        "generation centre, which holds the master secret s and issues partial private keys. It "
        "maintains the inter-TA trust matrix and per-RTA reliability scores, stores a sealed "
        "escrow copy of every entity's public credentials, and keeps a federated directory of "
        "temporary identities. It mediates every cross-region, load-sharing or fail-over request.",
        "**Load balancer.** For every request the load balancer scores the operational, trusted "
        "RTAs by load, availability, reliability and communication delay, and picks the best. "
        "An RTA whose load exceeds a limit is bypassed, so a disaster hot-spot does not "
        "overload a single RTA.",
        "**Fault-tolerance procedure.** RTAs send heartbeats. A missing heartbeat, or a timeout "
        "together with a missing heartbeat, marks an RTA as down, and its traffic moves to "
        "another trusted RTA. A recovered RTA is resynchronised by the Root TA.",
        "**ASCON AEAD security layer.** Every protocol message, every inter-TA message and the "
        "post-authentication data channel are protected by ASCON, which gives confidentiality and "
        "integrity at low cost. The signatures travel inside the ciphertexts.",
        "**Certificateless authentication module.** Partial private keys are validated before "
        "use, full keys never leave the entity, and every signature is bound to the session's "
        "nonces, the temporary identity, the serving RTA and a timestamp. Replacing a public key "
        "or abusing the KGC's knowledge of partial keys does not yield a valid signature.",
        "**Identity and session update.** Each successful run refreshes the vehicle's temporary "
        "identity with a hash of the old identity, a fresh nonce and the session time. The old "
        "and current values are both accepted, so lost messages cannot cause desynchronisation, "
        "and the update is pushed to the federation.",
        "**Revocation registry.** Compromised or retired vehicles and UAVs are recorded in a "
        "versioned registry at the Root TA. The registry is pushed to every RTA, and RTAs that "
        "were offline catch up when they rejoin.",
        "**Recovery / re-enrolment.** A revoked or damaged entity is re-admitted with new "
        "credentials and a new key pair while every other entity keeps working, so the network "
        "never needs a reset.",
        "**Post-quantum lightweight layer.** A configuration switch moves all AEAD operations to "
        "Ascon-80pq with 160-bit keys, raising resistance to quantum key search on the symmetric "
        "layer without changing message formats.",
        "**Evaluation layer.** The design is measured for authentication speed, traffic, "
        "computation, storage, energy and security, under high mobility, changing link "
        "conditions, overload and failures.",
    ])
    R.h2("3.2 Operational workflow")
    R.bullets([
        "**Step 1 – Secure enrolment.** Each vehicle and UAV registers once with an RTA of its "
        "region over a secure provisioning channel. It generates a secret value, obtains a "
        "partial private key from the KGC through the RTA, validates it and forms its full "
        "private key. The RTA registers the public key and deposits a sealed copy of the "
        "credentials with the Root TA.",
        "**Step 2 – Regional TA selection.** The load balancer computes the load, availability, "
        "reliability and delay terms of every eligible RTA and directs the request to the RTA "
        "with the highest score. This is normally the local RTA, but another RTA when the local "
        "one is busy, failed or less reliable.",
        "**Step 3 – Vehicle request.** The vehicle builds Msg1 from a fresh nonce, a timestamp and "
        "its temporary identity, signs the request with its certificateless private key, and "
        "protects everything with an ASCON key derived from its SELAP credentials.",
        "**Step 4 – Regional authentication.** The RTA checks freshness, replays and revocation, "
        "decrypts Msg1 and verifies the vehicle's signature. If the vehicle or UAV belongs to "
        "another region, the RTA obtains its credentials from the Root TA over an authenticated "
        "inter-TA link. It then sends Msg2 to the UAV.",
        "**Step 5 – UAV authentication and key agreement.** The UAV authenticates the RTA through "
        "the ASCON tag, derives the session key, signs its answer and returns Msg3. The RTA "
        "verifies the UAV's signature, refreshes the vehicle's temporary identity and sends Msg4. "
        "The vehicle derives the same session key and confirms it with the verifier.",
        "**Step 6 – Revocation.** A compromised entity is entered in the federated revocation "
        "registry, and all RTAs then reject its requests.",
        "**Step 7 – Recovery.** A legitimate entity whose credentials were lost or revoked is "
        "re-enrolled with fresh credentials and a new key pair, without disturbing anyone else.",
        "**Step 8 – Fail-over and load sharing.** When an RTA fails or saturates, requests are "
        "handled by other trusted RTAs using delegated credentials. When it returns, it is "
        "resynchronised.",
        "**Step 9 – Secure communication and evaluation.** Emergency data flows under the session "
        "key, and the complete system is measured under high mobility, lossy links, overload and "
        "failures.",
    ])
    R.h2("3.3 Mapping to the open issues of SELAP")
    R.table("SELAP limitations and how HF-SELAP addresses them",
            ["Limitation stated for SELAP [21]", "HF-SELAP mechanism", "Evaluated in"],
            [["Single TA limits scale in large or multi-domain deployments",
              "Regional TAs + Root TA, delegated authentication, score-based load balancing",
              "Sec. 5.6"],
             ["Single TA is a single point of failure",
              "Heartbeat monitoring, fail-over, resynchronisation", "Sec. 5.7"],
             ["Robustness under stress and high mobility not examined",
              "Event simulation with loss, queues, retries and moving vehicles", "Sec. 5.6–5.8"],
             ["PUF / fuzzy extractor adds hardware dependence and management complexity",
              "Certificateless keys: no special hardware, no helper data, remote re-enrolment",
              "Sec. 5.9"],
             ["No revocation or recovery of compromised entities",
              "Federated revocation registry, re-enrolment protocol", "Sec. 5.10"],
             ["No post-quantum migration path",
              "Ascon-80pq mode for the symmetric layer", "Sec. 5.3, 5.11"]],
            [6.2, 6.6, 2.2])

    # ---------------------------------------------------- methodology
    R.h1("4. Proposed Methodology")
    R.h2("4.1 System and threat model")
    R.p(
        "The system contains vehicles V_{t}, UAVs U_{k}, a set of Regional TAs and one Root TA "
        "that hosts the key generation centre (KGC). Vehicles and UAVs carry smart cards issued "
        "during enrolment, which hold their symmetric credentials and certificateless private "
        "keys. The attacker follows the Dolev–Yao model: it controls every public channel and can "
        "read, delete, delay, replay, modify and inject messages. Following the Canetti–Krawczyk "
        "extension used by SELAP, it may also learn ephemeral values, steal a smart card and read "
        "its contents, and try to guess passwords, but it cannot obtain a card's secrets and the "
        "matching password at the same time. For the certificateless layer we also consider the "
        "two standard adversaries: a Type-I adversary that can replace an entity's public key but "
        "does not know the master secret, and a Type-II adversary (a curious KGC) that knows the "
        "master secret and the partial keys it issued but not the entities' secret values. "
        "Regional TAs may crash, which is the failure case HF-SELAP adds, but they do not act "
        "maliciously. Inter-TA links run over a wired backhaul and are protected by per-RTA ASCON "
        "link keys issued by the Root TA. Clocks are loosely synchronised, and a message is "
        "accepted only if its timestamp is within ΔT of the receiver's clock.")
    R.table("Notation", ["Symbol", "Meaning"],
            [["ID_{V}, PW_{V} / ID_{U}, PW_{U}", "Identity and password of a vehicle / UAV"],
             ["PID_{V}, PID_{U}", "Pseudonymous identities (hash of identity and secret nonce)"],
             ["TID_{V}, TID^{o}, TID^{c}", "Temporary vehicle identity; old and current TA records"],
             ["k_{TA}, ID_{TA}", "Private master key and public identity of a Regional TA"],
             ["N_{UR1}, C_{U}", "UAV secret nonce and RTA-issued UAV credential"],
             ["G, n, s, P_{pub}", "P-256 base point and order; KGC master secret, P_{pub} = s·G"],
             ["x_{E}, X_{E}", "Secret value of entity E and its public value X_{E} = x_{E}·G"],
             ["R_{E}, D_{E}", "Public commitment and partial private key issued by the KGC"],
             ["SK_{E}, Q_{E}, σ_{E}", "Full private key, verification key and signature of E"],
             ["N_{x}, T_{x}", "128-bit nonce, 32-bit timestamp"],
             ["M_{x}, M^{a}, M^{b}", "256-bit credential and its two 128-bit halves"],
             ["h(·), ⊕, ∥", "SHA-256, bitwise XOR, concatenation"],
             ["Enc_{k}/Dec_{k}", "ASCON authenticated encryption / decryption"],
             ["SK_{HF}, SKV", "Session key and its 128-bit verifier SK_{HF}^{a} ⊕ SK_{HF}^{b}"]],
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
        "**Certificateless key generation.** HF-SELAP uses a pairing-free certificateless scheme "
        "on the NIST P-256 curve [25]. The KGC picks a master secret s and publishes "
        "P_{pub} = s·G. Entity E picks its secret value x_{E} and sends X_{E} = x_{E}·G. The KGC "
        "picks r_{E}, computes R_{E} = r_{E}·G and")
    R.eq("h_{E} = H_{1}(ID_{E} ∥ X_{E} ∥ R_{E} ∥ P_{pub}),    D_{E} = r_{E} + h_{E}·s  mod n")
    R.p(
        "The entity accepts D_{E} only if D_{E}·G = R_{E} + h_{E}·P_{pub}, and then forms its "
        "complete private key from both components:")
    R.eq("SK_{E} = x_{E} + D_{E}  mod n")
    R.p(
        "The public key PK_{E} = (X_{E}, R_{E}) is registered with the Regional TA, which "
        "derives the verification key")
    R.eq("Q_{E} = X_{E} + R_{E} + h_{E}·P_{pub} = SK_{E}·G")
    R.p("**Certificateless authentication proof.** For an authentication message M_{E}:")
    R.eq("σ_{E} = Sign(SK_{E}, M_{E}),      Verify(ID_{E}, Q_{E}, σ_{E}, M_{E}) = 1")
    R.p(
        "Sign and Verify are ECDSA with SHA-256 [24]. Because X_{E} is an input of h_{E}, an "
        "adversary who replaces an entity's public key changes h_{E}, so the partial key no "
        "longer matches and the adversary does not know the discrete logarithm of the new "
        "Q_{E}. The KGC knows D_{E} but not x_{E}, so it cannot sign for the entity either.")
    R.h2("4.3 Registration and login")
    R.p(
        "**Vehicle registration.** The vehicle picks ID_{V}, N_{VR1} and its secret value x_{V}, "
        "and sends PID_{V} = h(ID_{V} ∥ N_{VR1}) and X_{V} to its RTA. The RTA issues TID_{V} "
        "and N_{VR2}, obtains (R_{V}, D_{V}) from the KGC for ID_{E} = PID_{V} over the inter-TA "
        "link, derives Q_{V}, and stores the record ⟨TID^{o} = ⊥, TID^{c} = TID_{V}, N_{VR2}, "
        "M_{VR1}, Q_{V}⟩, where:")
    R.eq("M_{VR1} = PID_{V} ⊕ h(N_{VR2} ∥ k_{TA})")
    R.p(
        "The vehicle validates D_{V} and computes SK_{V} = x_{V} + D_{V}. Its smart card picks "
        "N_{VR3}, stores M_{VR2} = N_{VR3} ⊕ h(ID_{V} ∥ PW_{V}), and seals N_{VR1} ∥ N_{VR2} ∥ "
        "SK_{V} under the key derived from M_{VR3} = h(ID_{V} ∥ PW_{V} ∥ N_{VR3}). The RTA "
        "deposits a sealed copy ⟨handle, TID^{o}, TID^{c}, N_{VR2}, PID_{V}, Q_{V}⟩ with the "
        "Root TA.")
    R.p(
        "**UAV registration.** The RTA rejects identities already known to the federation. The "
        "UAV picks N_{UR1} and x_{U} and sends PID_{U} = h(ID_{U} ∥ N_{UR1}) and X_{U}. The RTA "
        "issues the credential C_{U}, obtains (R_{U}, D_{U}) for ID_{E} = ID_{U}, derives Q_{U} "
        "and stores:")
    R.eq("M_{UR1} = PID_{U} ⊕ h(ID_{U} ∥ C_{U} ∥ k_{TA})")
    R.p(
        "The UAV validates D_{U}, forms SK_{U} = x_{U} + D_{U}, and its smart card seals "
        "N_{UR1} ∥ C_{U} ∥ SK_{U} under the operator's password with the same construction as "
        "the vehicle card. The escrow copy deposited at the Root TA contains PID_{U}, C_{U} and "
        "Q_{U}.")
    R.p(
        "**Login.** Entering ID and PW lets the card recover its nonce from M_{VR2} (or M_{UR2}), "
        "rebuild the ASCON key and open the sealed credentials and private key. A wrong password "
        "fails the tag check. After five consecutive failures the card locks, which stops online "
        "guessing on a stolen card.")
    R.h2("4.4 Authentication and key agreement")
    bits = sc3["Intra-region (home RTA serves)"]["air_bits"]
    R.p(
        "Fig. 2 shows the exchange. It keeps SELAP's four messages and ASCON keys; the "
        "signatures and the serving-RTA identity travel inside the ciphertexts, which gives "
        f"message sizes of {bits['msg1']}, {bits['msg2']}, {bits['msg3']} and {bits['msg4']} bits.")
    R.figure(FIG / "fig_message_flow.png",
             "Message flow of one HF-SELAP authentication. Solid arrows are radio messages and "
             "dashed arrows are backhaul traffic added by the federation.", 15.0)
    R.bullets([
        "**A-1 (vehicle).** Computes PID_{V}, a nonce N_{A1}, a timestamp T_{1} and "
        "M_{A1} = h(PID_{V} ∥ N_{VR2} ∥ T_{1}). Signs "
        "σ_{V} = Sign(SK_{V}, TID_{V} ∥ N_{A1} ∥ ID_{U} ∥ ID_{TA} ∥ T_{1}), encrypts "
        "N_{A1} ∥ ID_{U} ∥ σ_{V}, and sends Msg1 = {TID_{V}, C_{A1}, Tag_{A1}, T_{1}}.",
        "**A-2 (RTA).** Checks |T_{R} − T_{1}| ≤ ΔT and the replay cache. Finds TID_{V} in "
        "TID^{o} or TID^{c} (fetching the record from the Root TA if it belongs to another RTA) "
        "and applies RevCheck. Recovers PID_{V} = M_{VR1} ⊕ h(N_{VR2} ∥ k_{TA}), decrypts Msg1 "
        "with M_{A2} = h(PID_{V} ∥ N_{VR2} ∥ T_{1}), and requires Verify(PID_{V}, Q_{V}, σ_{V}, "
        "·) = 1 before any foreign UAV record is fetched.",
        "**A-3 (RTA).** Looks up ID_{U} and applies RevCheck, recovers PID_{U}, picks N_{A2} and "
        "T_{2}, computes M_{A3} = h(PID_{V} ∥ N_{A2} ∥ T_{1}), the refreshed identity "
        "TID^{new} = h(TID_{V} ∥ N_{A2} ∥ T_{1}) and M_{A4} = h(PID_{U} ∥ C_{U} ∥ T_{2}), and sends "
        "Msg2 = {C_{A3}, Tag_{A3}, T_{2}} carrying N_{A1} ∥ N_{A2} ∥ M_{A3} ∥ ID_{TA}.",
        "**A-4 (UAV).** Computes PID_{U} = h(ID_{U} ∥ N_{UR1}) and decrypts Msg2 with "
        "M_{A5} = h(PID_{U} ∥ C_{U} ∥ T_{2}), which authenticates the RTA. Picks N_{A3} and "
        "T_{3}, computes M_{A6} = h(PID_{U} ∥ N_{A3} ∥ T_{3}), the session key SK_{HF} (below) "
        "and SKV, signs σ_{U} = Sign(SK_{U}, ID_{U} ∥ N_{A1} ∥ N_{A2} ∥ N_{A3} ∥ SKV ∥ ID_{TA} "
        "∥ T_{3}), and returns Msg3 = {C_{A5}, Tag_{A5}, T_{3}} carrying N_{A3} ∥ SKV ∥ σ_{U}.",
        "**A-5 (RTA).** Decrypts Msg3, requires Verify(ID_{U}, Q_{U}, σ_{U}, ·) = 1, computes "
        "M_{A9} = h(PID_{U} ∥ N_{A3} ∥ T_{3}), sets TID^{o} ← TID_{V} and TID^{c} ← TID^{new}, "
        "and sends Msg4 = {C_{A7}, Tag_{A7}, T_{4}} carrying N_{A2} ∥ N_{A3} ∥ M_{A9} ∥ SKV. The "
        "identity update is then written through to the Root TA asynchronously.",
        "**A-6 (vehicle).** Decrypts Msg4, recomputes M_{A3} and SK_{HF}, accepts only if "
        "SK_{HF}^{a} ⊕ SK_{HF}^{b} = SKV, and adopts TID^{new} = h(TID_{V} ∥ N_{A2} ∥ T_{1}).",
    ])
    R.p(
        "**Session key.** Both sides derive the key from the fresh nonces of vehicle and UAV, "
        "their session-bound pseudonyms, the serving RTA and the authenticated request:")
    R.eq("SK_{HF} = h(N_{V} ∥ N_{U} ∥ PID*_{V} ∥ PID*_{U} ∥ ID_{TA} ∥ M)")
    R.p(
        "with N_{V} = N_{A1}, N_{U} = N_{A3}, PID*_{V} = M_{A3}, PID*_{U} = M_{A6} = M_{A9} and "
        "M = ID_{U}. Communication starts only when SK_{VU} = SK_{UV}, which the vehicle checks "
        "through SKV.")
    R.p("**Identity refresh.** After every successful run the pseudonym is replaced by")
    R.eq("PID_{new} = h(PID_{old} ∥ N_{new} ∥ T),   here  TID^{new} = h(TID_{V} ∥ N_{A2} ∥ T_{1})")
    R.p(
        "truncated to 128 bits. The vehicle and the RTA compute it independently, so Msg4 does "
        "not need to carry it.")
    R.h2("4.5 Federation layer")
    R.p(
        "**Secure inter-TA link.** Each RTA shares an ASCON-128 link key with the Root TA. Every "
        "inter-TA message carries a header (sender, receiver, type, sequence number, timestamp) "
        "that is authenticated as associated data. Sequence numbers must strictly increase, so "
        "inter-TA replays are rejected as well.")
    R.p(
        "**Revocation check and delegated authentication.** Every RTA applies")
    R.eq("RevCheck(ID) = 0 if ID ∈ RR,   1 if ID ∉ RR")
    R.p(
        "against its copy of the revocation registry RR. An RTA that lacks a credential raises a "
        "fetch request. The Root TA serves a request from TA_{b} for an entity of TA_{a} only if")
    R.eq("Trust(TA_{a}, TA_{b}) ≥ T_{min}  ∧  Auth_{Ra}(V) = 1")
    R.p(
        "that is, the home RTA trusts the requester at or above T_{min} = 0.6 and the entity "
        "holds a current, unrevoked registration at its home RTA. The serving RTA caches the "
        "record for 60 s and runs the unchanged steps, using PID_{V} and PID_{U} directly instead "
        "of unmasking them with the home RTA's k_{TA}, which never leaves the home RTA.")
    R.p(
        "**Federated trust update.** After every service by TA_{j} for an entity of TA_{i}, "
        "the trust evolves with the latest observation S_{ij} (1 for a successful "
        "authentication, 0 for a failure):")
    R.eq("Trust_{ij}^{new} = α·Trust_{ij}^{old} + (1 − α)·S_{ij},    0 ≤ α ≤ 1,  α = 0.9")
    R.p("The reliability R_{i} of each RTA used by the load balancer follows the same rule.")
    R.p(
        "**Consistent identity updates.** After A-5 the serving RTA sends the new ⟨TID^{o}, "
        "TID^{c}⟩ pair to the Root TA, which updates the escrow and directory and forwards the "
        "change to the home RTA and to any RTA holding a cached copy. An update whose TID^{o} is "
        "no longer one of the identities the Root TA has on record is ignored. This prevents a "
        "delayed message from rolling a vehicle back to an old identity.")
    R.p("**Dynamic Regional-TA selection and load balancing.** The normalised load of TA_{i} "
        "is the ratio of its queued requests Q_{i} to its capacity C_{i}, and the delay term is "
        "normalised over the candidates:")
    R.eq("L_{i} = Q_{i} / C_{i},        D_{i}^{score} = (D_{max} − D_{i}) / (D_{max} − D_{min})")
    R.eq("Score(TA_{i}) = w_{1}(1 − L_{i}) + w_{2}A_{i} + w_{3}R_{i} + w_{4}D_{i}^{score},   "
         "w_{1} + w_{2} + w_{3} + w_{4} = 1")
    R.eq("TA* = arg max_{i} Score(TA_{i})")
    R.p(
        "The weights are (w_{1}, w_{2}, w_{3}, w_{4}) = (0.45, 0.15, 0.20, 0.20). A_{i} is the "
        "share of the last 10 s in which TA_{i}'s heartbeats arrived on time, R_{i} its "
        "reliability, and D_{i} the expected access delay (10 ms in-region, 25 ms cross-region). "
        "The maximisation runs only over eligible RTAs: operational, trusted by the entity's "
        "home RTA, and with L_{i} ≤ L_{max} = 0.9, so a request is redirected when L_{i} > L_{max} "
        "while another RTA is available.")
    R.p(
        "**Fault-tolerant fail-over.** RTAs send a heartbeat every 500 ms. An RTA is treated as "
        "down after three missed heartbeats, or earlier if a request to it times out while at "
        "least one heartbeat is missing. The replacement is chosen by the same score:")
    R.eq("TA_{fallback} = arg max_{j} Score(TA_{j})   s.t.  Status(TA_{j}) = 1  ∧  "
         "Trust(TA_{j}, TA_{i}) ≥ T_{min}")
    R.p(
        "A vehicle whose attempt times out (1.5 s) retries through another RTA, up to three "
        "attempts. A recovering RTA receives every revocation and identity update it missed "
        "before it serves again.")
    R.p(
        "**Revocation and recovery.** Revoking an entity adds its handle to a versioned registry "
        "and pushes a REVOKE message to every operational RTA, which drops the entity from its "
        "indexes and caches. Recovery revokes the old handle (if it is not already revoked) and "
        "enrols the entity again: a vehicle receives a new temporary identity, N_{VR2} and key "
        "pair, and a UAV a new credential C_{U} and key pair.")
    R.h2("4.6 Implementation")
    R.p(
        f"HF-SELAP is written in Python {env['python']} and uses NumPy (simulation statistics), "
        "Matplotlib (figures) and the cryptography package. ASCON v1.2 was implemented from the "
        "specification and agrees byte-for-byte with the published reference implementation on "
        "the official test vector and on random inputs for both variants. SHA-256 comes from the "
        "Python standard library. ECDSA signing and verification and base-point multiplication on "
        "P-256 use OpenSSL through the cryptography package; the remaining curve arithmetic of the "
        "enrolment (point addition and h_{E}·P_{pub} with a precomputed window table) is written "
        "in Python and checked against OpenSSL by the tests. "
        f"Table {R.tab_no + 1} lists the modules. {n_tests} unit and security tests check "
        "functional correctness, operation counts, certificateless key handling, federation "
        "behaviour and every attack scenario.")
    R.table("Implementation modules",
            ["Module", "Responsibility"],
            [["ascon.py", "ASCON-128 and Ascon-80pq AEAD (pure Python)"],
             ["primitives.py", "h(·), key derivation, 32-bit timestamps, simulated clock, op meter"],
             ["certificateless.py", "KGC, partial keys, key validation, Q_{E}, ECDSA on P-256"],
             ["messages.py", "Wire formats of Msg1–Msg4, signed inputs, inter-TA messages"],
             ["entities.py", "Smart cards, vehicle (A-1, A-6), UAV (A-4), session key, TID refresh"],
             ["ta.py", "Regional TA: enrolment, A-2/A-3/A-5, signature checks, dual records"],
             ["federation.py", "Root TA: KGC, links, trust update, escrow, TID sync, revocation"],
             ["loadbalancer.py", "Health monitor, availability A_{i}, selection score, L_{max}"],
             ["system.py", "Facade: topology, enrolment, authentication, recovery"],
             ["channel.py", "ASCON data channel keyed by the session key"],
             ["simulation.py", "Discrete-event network simulator, T_{auth} decomposition, LI"],
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
        "step, so queueing grows out of real costs. An RTA queue holds at most C_{i} = 200 "
        "requests, and an overloaded RTA answers 'busy' so the vehicle can retry elsewhere. "
        "Timestamps are checked against simulated time, including queueing delay. Federation "
        "synchronisation runs asynchronously, and its CPU time is recorded separately. The "
        "'single TA' baseline is the same code with one RTA, in which case no federation traffic "
        "is generated. Three metrics follow the formulation directly. The authentication delay "
        "of every successful request is split into its components,")
    R.eq("T_{auth} = T_{req} + T_{TA} + T_{authz} + T_{UAV} + T_{resp}")
    R.p(
        "namely Msg1 uplink with step A-1, RTA queueing and processing, delegated credential "
        "fetches from the Root TA, the RTA–UAV–RTA leg, and the Msg4 downlink with step A-6. "
        "Time lost in earlier, failed attempts is reported separately. The communication overhead "
        "is the size of all protocol messages, and the balance of the RTAs is measured by the "
        "load-imbalance metric over their utilisations L_{i}:")
    R.eq("CO_{HF} = Σ_{i=1..n} |Msg_{i}|,        LI = √( (1/n) Σ_{i=1..n} (L_{i} − L̄)² ),   "
         "L̄ = (1/n) Σ_{i=1..n} L_{i}")

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
    prim_tab = R.tab_no
    asc = prim["Ascon-128 encryption, 64 B (Ta)"]["mean"]
    asc_pq = prim["Ascon-80pq encryption, 64 B"]["mean"]
    t_sign = prim["ECDSA P-256 signing (Ts)"]["mean"]
    t_ver = prim["ECDSA P-256 verification (Tv)"]["mean"]
    R.p(
        f"SHA-256 runs in native code and costs about {f(prim['SHA-256 hash (Th)']['mean'], 4)} ms, "
        f"while the pure-Python ASCON needs about {f(asc, 3)} ms to encrypt a 64-byte payload. "
        "ASCON therefore dominates protocol cost in this prototype. A native or hardware ASCON "
        "would be one to two orders of magnitude faster, so the absolute numbers below are "
        "conservative. Ascon-80pq costs essentially the same as Ascon-128 "
        f"({f(asc_pq, 3)} ms): the two variants share the permutation and differ only in key "
        "loading. The certificateless operations run in native OpenSSL code: an ECDSA signature "
        f"costs {f(t_sign, 3)} ms and a verification {f(t_ver, 3)} ms, each "
        "less than one pure-Python ASCON call.")
    R.h2("5.3 Computation cost, post-quantum mode and energy")
    ops = intra["ops_steady"]

    def opstr(d):
        parts = []
        for key, sym in (("hash", "T_{h}"), ("ascon", "T_{a}"), ("sign", "T_{s}"),
                         ("verify", "T_{v}")):
            if d.get(key):
                parts.append(f"{d[key] if d[key] > 1 else ''}{sym}")
        return " + ".join(parts)

    rows = []
    for label, sc_ in (("Single TA (no federation)", base), ("HF-SELAP intra-region", intra),
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
    R.p(
        "In the table, T_{h}, T_{a}, T_{s} and T_{v} are one hash, ASCON operation, signature and "
        "verification; T_{p} and T_{f} are SELAP's PUF evaluation and fuzzy-extractor "
        "reproduction.")
    R.figure(FIG / "fig_cost_per_entity.png",
             "Per-entity computation time of one authentication (error bars: 95 % confidence "
             "intervals).", 15.0)
    R.p(
        "The counts show exactly what the certificateless design changes with respect to "
        "SELAP's cost model. The UAV no longer evaluates a PUF or runs a fuzzy extractor; it "
        "signs once instead. The vehicle signs once and computes one extra hash for the "
        "identity refresh, and the serving TA computes that hash as well and verifies the two "
        "signatures. The federation itself adds nothing to the vehicle or the UAV. On the "
        f"authentication path the serving TA costs {f(intra['ta']['mean'], 3)} ms in HF-SELAP "
        f"against {f(base['ta']['mean'], 3)} ms with a single TA. In a cross-region run the TA "
        "performs one hash fewer, because the delegated record already contains PID_{U}. The "
        "extra work the federation introduces is the asynchronous identity write-through, about "
        f"{f(intra['sync']['mean'], 3)} ms of combined RTA and Root TA time. It runs after Msg4 "
        "has been sent, so it does not delay the vehicle. The first cross-region request to a "
        f"given UAV also pays a one-time credential fetch: {f(cross['first_run']['ta'], 3)} ms at "
        f"the TA against {f(cross['ta']['mean'], 3)} ms once cached. The post-quantum mode "
        f"changed the total by {f(pq_delta, 1)} %, in line with the small difference between the "
        f"two ASCON variants in Table {prim_tab}.")
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
    R.table("Measured traffic per authentication (bits)",
            ["Scenario", "Air interface", "Backhaul (wired)", "Backhaul messages"],
            [[k, v["air_total"], v["backhaul_total"],
              ", ".join(f"{n} ×{d['messages']}" for n, d in v["backhaul"].items())]
             for k, v in sc3.items()],
            [5.4, 2.2, 2.6, 4.8])
    cp = e3["control_plane"]
    bigger = sorted(n for n, b in ecc.items() if b > air)
    smaller = {n: b for n, b in ecc.items() if b <= air}
    sync_bits = sc3["Intra-region (home RTA serves)"]["backhaul_total"]
    enrol_v = sum(d["bits"] for d in cp["deposit_vehicle"].values())
    enrol_u = sum(d["bits"] for d in cp["deposit_uav"].values())
    if smaller:
        cmp_text = (f"That is still less than {len(bigger)} of the {len(ecc)} elliptic-curve "
                    "schemes compared in [21]; " +
                    "; ".join(f"{n} needs {b} bits ({f(100 * (air - b) / b, 1)} % fewer)"
                              for n, b in smaller.items()) + ". ")
    else:
        cmp_text = (f"That is still {f(100 * (1 - air / min(ecc.values())), 0)}–"
                    f"{f(100 * (1 - air / max(ecc.values())), 0)} % less than the "
                    f"{len(ecc)} elliptic-curve schemes compared in [21]. ")
    R.p(
        f"HF-SELAP sends {air} bits over the radio links in every scenario, which matches "
        f"CO_{{HF}} = Σ|Msg_{{i}}| over the four messages. That is {air - selap_air} bits more than "
        f"SELAP's {selap_air}: the two 512-bit signatures and the 128-bit RTA identity that "
        "the certificateless layer adds. " + cmp_text +
        "The federation's traffic stays on the wired backhaul. A routine authentication adds one "
        f"{sync_bits}-bit identity-sync message. A cross-region or fail-over authentication "
        "additionally fetches the missing credential once, and later requests hit the cache. The "
        f"remaining control-plane traffic is small: one heartbeat is {cp['heartbeat_bits']} bits "
        "per RTA every 500 ms, a federation-wide revocation costs "
        f"{cp['revocation_broadcast']['revoke']['bits']} bits for three RTAs, and enrolment, "
        "including the partial-private-key request and answer, costs "
        f"{enrol_v} bits per vehicle and {enrol_u} bits per UAV.")
    R.h2("5.5 Storage cost")
    stg = e3["storage_bits"]
    puf_card = 8 * (32 + 16 + 112 + 16)        # M_UR2 + C_K(C_U + 896-bit helper) + tag
    R.table("Long-term storage (bits)", ["Item", "HF-SELAP (measured)", "SELAP (reported [21])"],
            [["Vehicle smart card", stg["Vehicle smart card"], 768],
             ["UAV smart card", stg["UAV smart card"], 656],
             ["Regional TA, per own vehicle",
              stg["Regional TA, per own vehicle <TID_o,TID_c,N_VR2,M_VR1,Q_V>"], "–"],
             ["Regional TA, per own UAV", stg["Regional TA, per own UAV <ID_U,M_UR1,C_U,Q_U>"],
              "–"],
             ["Regional TA, per cached foreign vehicle",
              stg["Regional TA, per cached foreign vehicle <TID_o,TID_c,N_VR2,PID_V,Q_V>"], "–"],
             ["Root TA escrow, per vehicle", stg["Root TA escrow, per vehicle (sealed)"], "–"],
             ["Root TA escrow, per UAV", stg["Root TA escrow, per UAV (sealed)"], "–"]],
            [7.0, 4.0, 4.0])
    R.p(
        f"The vehicle card holds {stg['Vehicle smart card']} bits: SELAP's 768 plus the "
        "256-bit private key SK_{V}. The UAV card holds N_{UR1}, C_{U} and SK_{U} in "
        f"{stg['UAV smart card']} bits. That is more than the 656 bits estimated in [21], which "
        "assumes 144 bits of fuzzy-extractor helper data, but less than a PUF-based card with a "
        f"concrete repetition-code fuzzy extractor (896-bit helper data) would need: {puf_card} "
        "bits. Each RTA record grows by the 264-bit compressed verification key. Federation "
        "storage stays on servers: about one kilobit of escrow per entity at the Root TA, and a "
        "cached record only for foreign entities an RTA has actually served.")
    R.h2("5.6 Scalability, load balancing and delay decomposition")
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
        rows.append([name, f"≥ {cap_}" if cap_ == top_rate else (f"{cap_}" if cap_ else "–"),
                     f(100 * p_["success_rate"], 1), f(p_["mean_latency_ms"], 1),
                     f(p_["p95_latency_ms"], 1),
                     "–" if name == sc_names[0] else f(p_["load_imbalance"], 3)])
    R.table(f"Scalability summary (capacity = highest tested load with ≥ 99 % success; other "
            f"columns at {top_rate} requests/s)",
            ["Deployment", "Capacity (req/s)", "Success (%)", "Mean latency (ms)",
             "p95 latency (ms)", "Load imbalance LI"],
            rows, [5.0, 2.0, 1.8, 2.1, 2.1, 2.0])
    low_rate = rates[0]
    rows = []
    for name in sc_names:
        for rate in (low_rate, top_rate):
            b = at_rate(name, rate)["t_auth_breakdown_ms"]
            if not b:
                rows.append([name, rate] + ["–"] * 7)
                continue
            rows.append([name, rate, f(b["T_req"], 1), f(b["T_TA"], 1), f(b["T_authz"], 1),
                         f(b["T_UAV"], 1), f(b["T_resp"], 1), f(b["earlier_attempts"], 1),
                         f(sum(b.values()), 1)])
    R.table("Decomposition of the mean authentication delay T_{auth} of successful requests (ms)",
            ["Deployment", "Load (req/s)", "T_{req}", "T_{TA}", "T_{authz}", "T_{UAV}",
             "T_{resp}", "Earlier attempts", "T_{auth}"],
            rows, [4.4, 1.5, 1.3, 1.3, 1.3, 1.3, 1.3, 1.6, 1.4], font=8.5)
    b_lb_top = lb3_top["t_auth_breakdown_ms"]
    b_base_top = base_top["t_auth_breakdown_ms"]
    R.p(
        "A single TA becomes the bottleneck as soon as the offered load exceeds its service "
        "capacity. Its queue fills, requests wait past their timeouts or are refused, and "
        f"success falls to {f(100 * base_top['success_rate'], 1)} % at {top_rate} requests/s "
        f"(it sustained ≥ 99 % up to {cap_base} requests/s). Adding RTAs without load balancing "
        "helps, but only partly. The hot-spot RTA still receives 70 % of the traffic while the "
        f"others sit partly idle: the load imbalance is LI = {f(static_top['load_imbalance'], 3)} "
        f"and success {f(100 * static_top['success_rate'], 1)} %. With the score-based load "
        "balancer, requests spill over to less loaded RTAs once the hot-spot queue grows, the "
        f"imbalance drops to LI = {f(lb3_top['load_imbalance'], 3)}, and three RTAs "
        f"authenticated {f(100 * lb3_top['success_rate'], 1)} % at {top_rate} requests/s "
        + (f"(≥ 99 % up to {cap_lb3} requests/s)" if cap_lb3 else "")
        + f"; two balanced RTAs reached {f(100 * lb2_top['success_rate'], 1)} %. The delay "
        "decomposition shows where the time goes. At light load T_{auth} is dominated by the "
        "radio and backhaul hops, and T_{TA} is a few milliseconds. At "
        f"{top_rate} requests/s the single TA's successful requests spend "
        f"{f(b_base_top['T_TA'], 0)} ms queueing and being processed at the TA, against "
        f"{f(b_lb_top['T_TA'], 0)} ms with three balanced RTAs, whose fetches of delegated "
        f"credentials (T_{{authz}} = {f(b_lb_top['T_authz'], 1)} ms on average) cost far less "
        "than the queueing they avoid.")
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
        f"{f(detect_s, 2) if detect_s is not None else '–'} s. Requests already sent to it time "
        "out and are retried at the next-best RTA chosen by TA_{fallback}. "
        + ("Every request of the outage window was eventually served: "
           if f_hf["outage_success_pct"] >= 99.95 else "Of the outage-window requests, ")
        +
        f"{f(f_hf['outage_timely_pct'], 1)} % within one second and "
        f"{f(f_hf['outage_success_pct'], 1)} % overall. The latency spike is limited to the "
        "detection window. When RTA-1 returns, the Root TA replays the identity updates and "
        "revocations it missed, so its vehicles authenticate normally again; its availability "
        "term A_{i} then recovers over the following seconds.")
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
        f"% per vehicle hop at {top_speed} km/h. Retries keep the success rate of both the "
        "single-TA deployment and HF-SELAP at or above "
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
    R.h2("5.9 Certificateless key management")
    R.figure(FIG / "fig_cl_operations.png",
             f"Mean execution time of the certificateless operations ({e8['runs']} runs each) "
             f"and of complete enrolments ({e8['enrolments']} vehicles and UAVs).", 15.0)
    R.figure(FIG / "fig_cl_composition.png",
             "Composition of the per-authentication computation, estimated from measured "
             "primitive costs and counted operations.", 15.0)
    rows = [[k, f(v["mean"], 4), f(v["sd"], 4)] for k, v in e8["operations"].items()]
    rows += [["Complete vehicle enrolment (VR-1 to VR-3)", f(e8["enrolment"]["vehicle"]["mean"], 3),
              f(e8["enrolment"]["vehicle"]["sd"], 3)],
             ["Complete UAV enrolment (UR-1 to UR-3)", f(e8["enrolment"]["uav"]["mean"], 3),
              f(e8["enrolment"]["uav"]["sd"], 3)]]
    R.table("Cost of certificateless key management", ["Operation", "Mean (ms)", "Std. dev. (ms)"],
            rows, [9.5, 2.8, 2.8])
    ops8 = e8["operations"]
    R.p(
        "Key management is a one-time cost paid at enrolment. Generating the secret value "
        f"({f(ops8['Secret value x_E, X_E = x_E G (entity)']['mean'], 3)} ms) and forming the "
        f"full key ({f(ops8['Full private key SK_E = x_E + D_E (entity)']['mean'], 3)} ms) use "
        "native code. Validating "
        f"the partial key ({f(ops8['Partial-key validation (entity)']['mean'], 3)} ms) and deriving "
        f"the verification key Q_{{E}} ({f(ops8['Verification key Q_E (RTA)']['mean'], 3)} ms) are "
        "the most expensive steps, because they compute h_{E}·P_{pub} in Python with a "
        "precomputed table. A complete enrolment, including the KGC round trip over the inter-TA "
        f"link and the escrow deposit, took {f(e8['enrolment']['vehicle']['mean'], 2)} ms for a "
        f"vehicle and {f(e8['enrolment']['uav']['mean'], 2)} ms for a UAV. Per authentication, "
        "the certificateless layer accounts for an estimated "
        f"{f(cl_share('vehicle'), 1)} % of the vehicle's computation, {f(cl_share('uav'), 1)} % "
        f"of the UAV's and {f(cl_share('ta'), 1)} % of the serving RTA's; the pure-Python ASCON "
        "dominates everywhere. Unlike SELAP's PUF-based enrolment, no repeated measurements of "
        "the device are needed, there is no helper data to store, and a UAV can be "
        "re-enrolled remotely with a new key pair. Security of the keys themselves is "
        "exercised in Section 5.11: a forged partial key is rejected at enrolment, and neither "
        "a replaced public key nor the KGC's own partial key yields a valid signature.")
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
        "one message per RTA, and recovering it is one enrolment with a new key pair. Without a "
        "recovery protocol, replacing compromised credentials safely would mean re-enrolling all "
        f"{rev_big['N']} vehicles: {f(rev_big['full_reset_ms'], 0)} ms of computation and "
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
        f"All {total} attacks were blocked. The certificateless scenarios show defence in depth: "
        "an adversary that knows a vehicle's or UAV's symmetric credentials, for example from a "
        "leaked TA database, still fails the signature "
        "check, and a Msg1 redirected to another RTA fails because ID_{TA} is signed. The "
        "ablation confirms that the defences are necessary: with dual temporary-identity records "
        f"disabled, the desynchronisation attack succeeds ({abl['observed']}). Table "
        f"{R.tab_no + 1} summarises the security and functional properties.")
    R.table("Security and functional properties",
            ["Property", "SELAP [21]", "HF-SELAP"],
            [["Mutual authentication and session-key agreement", "✓", "✓"],
             ["Anonymity and untraceability (rotating TID)", "✓", "✓ (signatures encrypted)"],
             ["Replay, MitM, impersonation, forgery resistance", "✓", "✓"],
             ["Smart-card loss resistance", "✓", "✓ + lockout"],
             ["Desynchronisation resistance", "✓", "✓ (federation-consistent)"],
             ["Hardware-bound UAV identity (PUF)", "✓", "– (replaced)"],
             ["Certificateless public-key authentication", "✗", "✓"],
             ["Resistance to key replacement and malicious KGC", "–", "✓"],
             ["Multiple trusted authorities / cross-region service", "✗", "✓"],
             ["Load balancing", "✗", "✓"],
             ["TA fault tolerance", "✗", "✓"],
             ["Revocation of compromised entities", "✗", "✓"],
             ["Recovery / re-enrolment without reset", "✗", "✓"],
             ["Post-quantum key length option", "✗", "✓ (Ascon-80pq)"]],
            [8.6, 2.6, 3.8])
    R.p(
        "**Post-quantum considerations.** SELAP uses only symmetric primitives. HF-SELAP adds "
        "elliptic-curve signatures, which Shor's algorithm would break on a large quantum "
        "computer. The design limits the consequences in two ways. First, the signatures only "
        "authenticate: the session key is derived from nonces carried under ASCON keys built from "
        "symmetric credentials, so breaking ECDSA later does not decrypt recorded sessions. "
        "Second, impersonating an entity needs both a valid signature and that entity's "
        "symmetric credentials, so against a quantum adversary the protocol falls back to the "
        "security of its symmetric layer. Grover's search roughly halves the effective length "
        "of symmetric keys: Ascon-128 offers about 64-bit security against quantum key search, "
        "the Ascon-80pq mode raises this to about 80 bits, and SHA-256 keeps roughly 128-bit "
        f"preimage resistance. The mode changed neither message sizes nor storage and moved total "
        f"computation by {f(pq_delta, 1)} %. A fully quantum-safe certificateless layer would "
        "need a lattice-based signature scheme, at the cost of much larger signatures.")
    R.h2("5.12 Discussion and limitations")
    R.p(
        "The results show that the federation layer adds availability, scalability and life-cycle "
        "security, and that certificateless keys can replace PUF hardware while keeping SELAP's "
        "lightweight ASCON structure. The certificateless layer costs one signature on each end "
        f"device, two verifications at the RTA and {air - selap_air} extra bits on the radio "
        "links. The federation's own costs fall on the wired backhaul and on servers, which are "
        "the resources that can most easily be provisioned. Several limitations remain. Without "
        "a PUF, a UAV's private key is protected by its smart card and password, so an attacker "
        "who obtains both can clone the UAV until it is revoked; a tamper-resistant secure element "
        "would restore hardware binding. The KGC is needed only at enrolment, not for "
        "authentication. The prototype runs in one process with simulated links, so the absolute "
        "timings are those of a Python implementation on a desktop CPU. As in SELAP, TAs are "
        "fully trusted and can compute session keys, and escrowing pseudonymous credentials at "
        "the Root TA widens that trusted base. The speed-dependent loss model is an assumption, "
        "and real UAV-to-vehicle channels should be measured. Clock synchronisation within ΔT is "
        "assumed rather than enforced.")

    # ----------------------------------------------------- conclusion
    R.h1("6. Conclusion")
    R.p(
        "This project designed, implemented and evaluated HF-SELAP, which extends the lightweight "
        "SELAP authentication protocol for UAV-assisted VANETs from a single trusted authority to "
        "a hierarchical federation of Regional TAs under a Root TA, and replaces SELAP's PUF and "
        "fuzzy extractor with pairing-free certificateless authentication. Each vehicle and UAV "
        "holds a private key SK = x + D that no single party knows, and signs its request inside "
        f"the ASCON-protected messages; the exchange stays at four messages and {air} bits. "
        "Around it, HF-SELAP adds score-based Regional-TA selection and load balancing, "
        "federated trust management, delegated cross-region authentication, heartbeat fail-over "
        "with resynchronisation, a federated revocation registry, identity refresh, recovery by "
        f"re-enrolment and an Ascon-80pq mode. In the measurements, the vehicle needed "
        f"{f(intra['vehicle']['mean'], 3)} ms and the UAV {f(intra['uav']['mean'], 3)} ms of "
        f"computation per authentication. Three balanced RTAs sustained "
        f"{f(100 * lb3_top['success_rate'], 1)} % success at {top_rate} requests/s where a single "
        f"TA managed {f(100 * base_top['success_rate'], 1)} %. During a TA outage, "
        f"{f(f_hf['outage_timely_pct'], 1)} % of requests were still served within one second. "
        f"All {total} attack scenarios were blocked. Future work includes a native and "
        "hardware-accelerated implementation on embedded UAV platforms, field trials with real "
        "5G/C-V2X radios, secure elements to protect the certificateless keys, a lattice-based "
        "certificateless signature for full post-quantum security, threshold techniques so that "
        "no single TA can derive session keys, and formal verification with tools such as "
        "ProVerif.")

    # ----------------------------------------------------- references
    R.h1("References")
    refs = REFERENCES
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
