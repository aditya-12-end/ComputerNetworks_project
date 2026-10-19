# HF-SELAP — Hierarchical Federated SELAP for UAV-Assisted VANETs

Implementation of the proposed work of the BCSE308L (Computer Networks) project
**"HF-SELAP: A Hierarchical Federated Lightweight Authentication Framework for
Secure UAV-Assisted VANET Communication in Disaster Rescue"**

* Vansh Garg — 24BCI0132
* Aditya Bhatt — 24BCI0143

HF-SELAP keeps the lightweight four-message SELAP exchange protected by ASCON AEAD
and SHA-256, but replaces SELAP's PUF and fuzzy extractor with **certificateless
public-key authentication**. Each vehicle and UAV combines its own secret value with
a partial private key from the key generation centre (SK = x + D) and signs its
protocol message; the Regional TA verifies the signature with the registered public
key (3584 air-interface bits per authentication). Around this core it adds the
extensions of the proposed work: several Regional TAs under a Root/Federation TA,
score-based TA selection and load balancing, federated trust management,
heartbeat-based fail-over, a federated revocation registry, identity refresh,
recovery by re-enrolment, a post-quantum (Ascon-80pq) mode, and a high-mobility /
stress evaluation layer.

## Quick start (Windows PowerShell)

**One-time setup.** Skip `python -m venv .venv` if the `.venv` folder already exists.
Running it while the environment is active fails with "Permission denied …
python.exe", because Windows will not overwrite the running interpreter. That
message is harmless.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Check that everything works (under a minute):**

```powershell
python demo.py                                   # guided walk-through of every feature
python -m unittest discover -s tests -t . -v     # 35 unit / security tests
```

**Regenerate the results.** Choose ONE of these, because both write the same result files:

```powershell
python experiments\run_all.py                    # full run used in the report (45-60 min)
python experiments\run_all.py --quick            # reduced sizes, for a fast check (about 10 min)
python experiments\run_all.py --only E5 E7       # run or resume selected experiments only
```

E5 (scalability) is the slowest step, at about 25 minutes. It prints a line as each
load point starts, so wait for it rather than pressing Ctrl+C. If a run is
interrupted, resume with `--only` and the experiments that did not finish.

**Rebuild the report from the results:**

```powershell
python report\build_report.py                    # writes HF-SELAP_Report.docx
```

Close the report in Word before rebuilding it, otherwise Windows blocks the file.
On Linux/macOS use `source .venv/bin/activate` and forward slashes.

## Repository layout

| Path                        | Purpose                                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------------ |
| `hfselap/ascon.py`        | Pure-Python ASCON v1.2 (Ascon-128 and Ascon-80pq), checked against the reference package               |
| `hfselap/primitives.py`   | h(·)=SHA-256, XOR, key derivation k = M^a ⊕ M^b, 32-bit timestamps, simulated clock, operation meter |
| `hfselap/certificateless.py` | Certificateless keys on P-256: KGC, partial key D, validation, SK = x + D, Q = X + R + h·P_pub, ECDSA |
| `hfselap/messages.py`     | Wire formats of Msg1–Msg4 and of inter-TA messages                                                    |
| `hfselap/entities.py`     | Smart cards, vehicles (A-1, A-6) and UAVs (A-4), signatures, session key, TID refresh                  |
| `hfselap/ta.py`           | Regional TA: registration, A-2/A-3/A-5, signature checks, dual TID records, replay cache, delegation   |
| `hfselap/federation.py`   | Root TA: KGC, secure inter-TA links, trust update, credential escrow, TID sync, revocation             |
| `hfselap/loadbalancer.py` | Health monitor (heartbeats, availability) and Score(TA_i) = w1(1-L)+w2A+w3R+w4D selection              |
| `hfselap/system.py`       | `HFSELAP` facade: topology, registration, authentication, revocation, re-enrolment                   |
| `hfselap/channel.py`      | ASCON data channel keyed by the session key                                                            |
| `hfselap/simulation.py`   | Discrete-event network simulator (latency, loss, queues, retries, failures, T_auth breakdown, LI)      |
| `hfselap/attacks.py`      | 26 executable attack scenarios + desynchronisation ablation                                            |
| `config.json`             | Every tunable parameter (validated by `hfselap/config.py`)                                           |
| `experiments/`            | E1–E10 experiment scripts and `run_all.py`                                                          |
| `results/`                | JSON results, `figures/` with every chart, `run_all.log`                                           |
| `report/`                 | `diagrams.py` (architecture + message flow) and `build_report.py`                                  |
| `tests/`                  | unittest suite                                                                                         |
| `_old_draft/`             | the earlier draft files, kept unchanged for reference                                                  |

`flow.txt` explains how the files depend on each other and how one
authentication flows through the code.

## What is measured

| Experiment                          | Script                 | Output                                             |
| ----------------------------------- | ---------------------- | -------------------------------------------------- |
| E1 primitive timings                | `exp_primitives.py`  | `results/e1_primitives.json`                     |
| E2 per-entity cost, PQ mode, energy | `exp_cost.py`        | `e2_cost.json`, `fig_cost_per_entity.png`      |
| E3/E4 communication + storage       | `exp_overhead.py`    | `e3_overhead.json`, `fig_comm_overhead.png`    |
| E5 scalability, load balancing, T_auth, LI | `exp_scalability.py` | `e5_scalability.json`, `fig_scalability_*.png` |
| E6 fault tolerance                  | `exp_fault.py`       | `e6_fault.json`, `fig_fault_*.png`             |
| E7 mobility + stress                | `exp_mobility.py`    | `e7_mobility.json`, `fig_mobility_*.png`       |
| E8 certificateless key management   | `exp_cl.py`          | `e8_cl.json`, `fig_cl_*.png`                   |
| E9 revocation + recovery            | `exp_revocation.py`  | `e9_revocation.json`                             |
| E10 attack scenarios                | `exp_security.py`    | `e10_security.json`                              |

Timings are measured on the machine that runs the scripts (recorded in
`results/environment.json`), so absolute milliseconds differ between computers;
message sizes, operation counts and security outcomes do not.

## Modelling assumptions (stated honestly)

* **Software prototype.** Vehicles, UAVs and TAs run in one Python process.
  Radio and backhaul links are simulated (latency, jitter, loss), not real 5G hardware.
* **Certificateless keys instead of a PUF.** Private keys are protected by the smart
  card and password, not by hardware; an attacker holding both can clone a device
  until it is revoked. ECDSA signing/verification and k·G use OpenSSL (via the
  `cryptography` package); the enrolment-only curve arithmetic is pure Python and is
  cross-checked against OpenSSL in `tests/test_certificateless.py`.
* **Air-interface cost.** The two 512-bit signatures and the 128-bit RTA identity make
  one authentication 3584 bits instead of SELAP's 2432.
* **Speed-dependent loss** in the mobility experiment is a modelling assumption,
  given explicitly in `exp_mobility.py`.
* **Trusted TAs.** As in SELAP, the TAs are fully trusted and can derive session keys.
  The federation also escrows pseudonymous credentials at the Root TA.
* **Post-quantum mode.** It enlarges the symmetric keys (Ascon-80pq, 160-bit). The
  certificateless layer uses elliptic curves and is therefore not quantum-safe; session keys
  do not depend on it, and impersonation also needs the symmetric credentials.

## Security note

This is an academic reference implementation. It has not had an independent
cryptographic review, and keys live in process memory.
