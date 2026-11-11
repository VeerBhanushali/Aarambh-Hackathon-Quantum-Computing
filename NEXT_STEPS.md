# Quantum Guard — Next Steps (hand-off)

Read this top to bottom before touching anything. **Feature freeze is in effect:** do the tasks below, fix only
bugs you hit while doing them, and do not add features.

---

## 1. Where things stand

| Area | Status |
|---|---|
| All 7 PS07 use cases + 8 technical expectations | Built and working (see README §2 for the mapping) |
| Guided demo (browser, end to end) | Passes, no JS errors — verified on OpenSSL 3.5.9, Linux |
| Tests | 21 / 21 pass on OpenSSL 3.5.9 (`pytest`) |
| Degraded mode (OpenSSL 3.0) | No crashes; clear errors + yellow banner; PQC tests skip |
| Docker image | Base `python:3.11-alpine3.22` ships OpenSSL **3.5.9** — **not yet run** (no Docker in the dev environment) |
| liboqs-python path | Optional; **untested**. App uses OpenSSL 3.5 for all PQC, which is enough |
| 8-slide deck | Drafted with this environment's numbers — **slide 7 must be re-measured** (task 3) |

Measured results to expect from the guided demo (if yours differ a lot, investigate before presenting):

- Discovery: 46 assets (15 network, 17 code, 14 certificate/key)
- Readiness: overall 30.4% → 47.8%, network TLS 33.3% → 86.7%
- Plan: 32 items (wave 1: 13, wave 2: 6, wave 3: 13), 10 auto-applied
- Policy tests 3 / 3 pass; dual-cert: old client gets `ecdsa_secp256r1_sha256`, new client gets `mldsa65`

Overall readiness stops at ~48% **by design**: the other 22 items are source-code/PKI changes a developer
must make. Say this in the demo before a judge asks.

---

## 2. Tasks, in order

Tick each box in this file (commit it) so the team sees progress.

### Task 1 — Get OpenSSL 3.5+ on the presentation laptop (30 min) — BLOCKER
Everything PQC needs it. Pick ONE:

```bash
docker compose up --build          # easiest, any OS; app on http://127.0.0.1:8000
```

```bash
brew install openssl@3 && bash scripts/run.sh       # macOS: Homebrew openssl@3 is 3.5+; run.sh finds it
```

```bash
nix build nixpkgs#openssl_3_5.bin --no-link --print-out-paths   # Linux / WSL2 (Ubuntu ships 3.0)
export OPENSSL_BIN=<printed path>/bin/openssl
bash scripts/run.sh
```

Windows: use Docker Desktop or WSL2. `scripts/run.ps1` only warns; Git-for-Windows OpenSSL is too old.

**Done when:** the top banner on the dashboard shows `ML-KEM: Enabled | ML-DSA: Enabled | SLH-DSA: Enabled`
and there is no yellow warning line.

- [ ] Task 1 done (method used: ______ , OpenSSL version: ______)

### Task 2 — Run the tests and the guided demo on that laptop (20 min)

```bash
OPENSSL_BIN=$OPENSSL_BIN python -m pytest -q
```
(Docker: `docker compose exec quantum-guard python -m pytest -q`)

Then in the browser: **Reset Demo → Run Guided Demo**. Wait for `100%`.

**Done when:** 21 passed; banner ends with `Guided Demo complete. Network TLS readiness 33.3% → 86.7% ...`;
Hybrid Lab shows a green check; PKI tab shows the two dual-cert clients; no red error toast.

- [ ] Task 2 done

### Task 3 — Re-run benchmarks and update the deck (30 min)
Benchmark numbers must come from the machine we present on.

1. Benchmarks tab → N = 200 → **Run Live Benchmarks** (takes ~1 minute). Do not use the laptop for anything else meanwhile; plug it in.
2. Click **Export CSV** and commit it as `docs/benchmarks-<laptop>.csv`.
3. Open the deck → slide 7. Replace the six table rows and the footer machine line with your numbers.
   The **Key takeaways** box on the Benchmarks tab already words the comparisons ("9.8x faster", "2.5x slower") for you.
4. If discovery/readiness counts differ from §1, update slides 3, 4 and 5 too.

Rules: never round in our favour; keep "slower" where it is slower. Write "quantum-resistant", never "quantum-proof".

- [ ] Task 3 done

### Task 4 — Record the backup video (30 min)
Screen-record the 5-minute demo script below at 1080p with voice-over. Keep it on the laptop AND a USB stick / cloud link.

- [ ] Task 4 done (link: ______ )

### Task 5 — Rehearse 3× with a timer (90 min)
Script (5:00 total). Speaker notes in each slide hold the full wording.

| Time | Do | Say |
|---|---|---|
| 0:30 | Slide 1 | Harvest now, decrypt later; 2030 deprecated, 2035 disallowed |
| 0:45 | Discovery tab: start enterprise, run scan, download CBOM | 3 scanners, 46 assets, CycloneDX CBOM |
| 0:45 | Risk tab: point at hr-records HNDL badge; move years-to-quantum slider | Mosca: 25 + 3 > 10 |
| 0:45 | Migration tab: plan → Apply → rescan | network 33% → 87%; rest is code, on purpose |
| 0:45 | Hybrid Lab: encrypt; tick Tamper; run 3 policy tests | secure if either algorithm holds |
| 0:30 | PKI tab: dual-certificate demo | old client ECDSA, new client ML-DSA |
| 0:30 | Benchmarks: one chart, one takeaway, machine specs | key exchange faster; cost is bytes |
| 0:30 | Slide 8 | vetted libraries, nothing hand-rolled, all measured live |

Before each rehearsal: **Reset Demo**. Keep a terminal with the server open in case it needs a restart.

- [ ] Rehearsal 1  - [ ] Rehearsal 2  - [ ] Rehearsal 3

### Task 6 — Confirm submission rules with the organisers (10 min)
Format, deadline, repo visibility, video length — none were in the problem statement PDF.

- [ ] Task 6 done (deadline: ______ , format: ______ )

### Task 7 — Final checklist (just before submitting)
- [ ] Guided demo runs end to end on the presentation laptop
- [ ] `pytest` all green on that laptop
- [ ] Deck benchmark slide shows numbers + specs from that laptop
- [ ] Backup video recorded and reachable offline
- [ ] Deck shared with teammates (the deck link is private until shared from its Share menu)
- [ ] `git status` clean; everything pushed

---

## 3. Optional, ONLY if Tasks 1–7 are done

| Item | Why | Effort |
|---|---|---|
| Install `liboqs-python` and run the Hybrid Lab once | Exercises the second ML-KEM backend (`app/crypto_lab/hybrid.py`) | 30–60 min (needs cmake + compiler) |
| Commit one real `s_client` output from the laptop into `tests/fixtures/` | Plan asked for a parser test on real output | 10 min |

Do **not** attempt: real host scanning, new algorithms, UI redesign.

---

## 4. Troubleshooting

| Symptom | Fix |
|---|---|
| Yellow banner "OpenSSL is 3.0…" | Task 1. Check `echo $OPENSSL_BIN` in the shell that starts the server |
| `Address already in use` on 8000 or 9441–9453 | `pkill -f "openssl s_server"; pkill -f uvicorn`, then start again |
| Demo state looks weird / old scans | **Reset Demo** button (keeps benchmarks), or stop server and `rm -rf data/` |
| Policy test "strict" fails | The strict server could not start: OpenSSL lacks ML-DSA. See Task 1 |
| Everything PQC broke after moving `data/` between machines | Keys are encrypted with `data/.master_key`; move the whole `data/` folder or delete it |
| Benchmark table shows `n/a` for p95/CPU on the first table | Expected: `openssl speed` only reports averages. The Python table has real p95 |

---

## 5. Where things live

| Path | What |
|---|---|
| `app/main.py` | All REST routes + executive report |
| `app/enterprise.py` | 5 simulated TLS services, profiles, dual-cert demo, `spawn_tls_server` (decrypts keys only at start-up) |
| `app/discovery/` | network / code / certs scanners, CBOM export |
| `app/risk.py`, `app/planner.py` | IR 8547 + Mosca scoring; waves, apply, compare |
| `app/pki.py`, `app/vault.py` | CAs, leaves, verify; encrypted key vault (`materialize_keys`) |
| `app/crypto_lab/` | Hybrid combiner, TLS policy tests |
| `app/benchmark.py` | openssl speed, handshakes, Python micro-benchmarks, computed takeaways |
| `app/static/` | Dashboard (HTML/JS/CSS) |
| `tests/` | `pytest`; `test_fixes.py` guards the review fixes (no plaintext keys, no invented numbers) |
