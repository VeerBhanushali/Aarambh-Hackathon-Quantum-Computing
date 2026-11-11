# Quantum Guard — Post-Quantum Cryptography Assessment & Migration Platform (PS07)

**Quantum Guard** is an end-to-end Post-Quantum Cryptography (PQC) discovery, risk assessment, migration planning, PKI dual-certificate serving, hybrid encryption combiner, and benchmarking platform built for problem statement **PS07**.

Every cryptographic operation, TLS handshake, certificate chain, and benchmark measurement is executed live using **OpenSSL 3.5+ CLI** (native FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and Python `cryptography` (X25519, ECDSA, RSA, HKDF-SHA256, AES-256-GCM)—with zero hand-rolled primitives and zero hard-coded fake data.

---

## 1. Architecture Diagram

```
Dashboard (HTML5 + Vanilla JS + Chart.js, served by FastAPI at GET /)
        │ REST JSON API (/api/*) + Printable HTML Report (/api/report)
FastAPI Application (app/main.py)
 ├── app/enterprise.py    Simulated Enterprise: 5 live TLS services (openssl s_server on ports 9441-9445)
 ├── app/discovery/       TLS network scanner (s_client) · AST/regex code scanner · X.509/key scanner · CycloneDX CBOM
 ├── app/risk.py          NIST IR 8547 (2030/2035) rules · Mosca HNDL shelf-life check · 0–100 risk scoring
 ├── app/planner.py       3-Wave migration recommendations · One-click auto-apply · Before/After verification
 ├── app/pki.py           Classical Root CA (ECDSA P-384) · PQC Root CA (ML-DSA-87) · SLH-DSA CA · Dual-cert demo
 ├── app/crypto_lab/      Hybrid KEM combiner (X25519 + ML-KEM-768 -> HKDF -> AES-256-GCM) · 3 TLS Policy Tests
 ├── app/benchmark.py     Empirical micro-benchmarks & TLS 1.3 handshake benchmarks + CSV export
 ├── app/vault.py         AES-256-GCM encrypted key vault (.enc, chmod 600) · Rotation tracker · Audit log
 └── app/db.py            SQLite persistence (data/quantum_guard.db)
```

---

## 2. PS07 Requirement & Technical Expectation Coverage Map

| PS07 Use Case | Module Implemented | Live Proof in Demo |
|---|---|---|
| **1. Cryptographic Discovery** | `app/discovery/network.py`, `code.py`, `certs.py`, `cbom.py` | Probes 5 live TLS services (`9441`–`9445`), scans synthetic Python/JS/Nginx codebase (17 rules), inspects X.509 certs & keys, and downloads **CycloneDX 1.6 CBOM JSON** (`GET /api/cbom/{scan_id}`). |
| **2. Quantum Vulnerability Assessment** | `app/risk.py` | Evaluates NIST IR 8547 status (2030 deprecation / 2035 disallowance), applies Mosca's theorem ($X + Y > Z$) strictly to key-establishment assets, and computes 0–100 scores. |
| **3. Post-Quantum Migration** | `app/planner.py` | Groups findings into 3 waves, provides crypto-agility wrapper patterns, auto-applies hybrid profiles to network services (`POST /api/apply`), and compares Before vs. After readiness (`GET /api/compare`). |
| **4. Hybrid Encryption** | `app/crypto_lab/hybrid.py`, `policy.py` | Combines ephemeral `X25519` + `ML-KEM-768` via transcript-bound `HKDF-SHA256` into `AES-256-GCM`, plus runs 3 live TLS 1.3 policy tests (Classical Fallback, Strict PQC-Only Rejection, Hybrid Negotiation). |
| **5. Performance Benchmarking** | `app/benchmark.py` | Measures wall median, p95, and CPU time + public key and ciphertext/signature byte sizes across X25519, ECDH, RSA, ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA, and live TLS 1.3 handshakes. |
| **6. Certificate Migration** | `app/pki.py`, `app/enterprise.py` | Initializes Classical ECDSA P-384 CA, PQC ML-DSA-87 CA, and SLH-DSA CA; issues/verifies/rotates leaves; runs `-cert`/`-dcert` Dual-Certificate server where legacy clients get ECDSA and PQC clients get ML-DSA-65. |
| **7. Security Dashboard** | `app/static/index.html`, `app.js`, `style.css` | Dark-theme SPA with KPI tiles, asset risk heatmap, migration waves chart, interactive Mosca sliders, one-click **Guided Demo**, and printable Executive Report (`GET /api/report`). |

| Technical Expectation | Implementation Details |
|---|---|
| **NIST PQC Standards** | `ALGORITHM_REGISTRY` in `app/config.py` tagged with FIPS 203, FIPS 204, FIPS 205, and NIST IR 8547 timeline panel. |
| **ML-KEM (FIPS 203)** | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` in Hybrid KEM combiner, `X25519MLKEM768` TLS 1.3 groups, and benchmarks. |
| **ML-DSA (FIPS 204)** | `ML-DSA-87` PQC Root CA, `ML-DSA-65` TLS leaf certificates, dual-cert serving, and signature benchmarks. |
| **SLH-DSA (FIPS 205)** | `SLH-DSA-SHA2-128s` Root CA, Wave 3 recommendation for long-lived roots/firmware signing, and benchmarks. |
| **Hybrid Protocols** | Application-level hybrid KEM (`X25519 + ML-KEM-768`) with HKDF transcript binding + TLS 1.3 `X25519MLKEM768`. |
| **PKI Lifecycle** | Root CA generation, CSR leaf signing with X.509v3 SAN extensions, `openssl verify` chain checks, live rotation. |
| **Benchmarking** | Empirical measurements with host CPU/OS/OpenSSL metadata and CSV export (`GET /api/benchmarks/{run_id}/csv`). |
| **Secure Key Management** | Private keys encrypted at rest with `AES-256-GCM` (`.enc`, `chmod 600`), rotation dates, audit log, and automated test verifying `"PRIVATE KEY"` never appears in any API response. |

---

## 3. Setup & Running

### Quick Start (Windows PowerShell)
```powershell
.\scripts\run.ps1
```

### Quick Start (Linux / macOS / WSL2 / Git Bash)
```bash
bash scripts/run.sh
```

Then open **http://127.0.0.1:8000** in your browser and click **▶ Run Guided Demo** in the top bar.

### Running Automated Tests
```powershell
python -m pytest -v
```

---

## 4. OpenSSL 3.5+ CLI Flags & Notes

Verified against `OpenSSL 3.5.6`:
- **Dual-Certificate Serving (`openssl s_server`)**: Uses `-cert <classical.crt> -key <classical.key> -dcert <mldsa65.crt> -dkey <mldsa65.key> -groups X25519MLKEM768:X25519`.
- **KEM Encapsulation/Decapsulation (`openssl pkeyutl`)**: Uses `-encap -pubin -inkey <pub.der> -keyform DER -out <ct.bin> -secret <ss.bin>` and `-decap -inkey <priv.pem> -in <ct.bin> -secret <ss.bin>`.
- **CycloneDX CBOM**: `GET /api/cbom/{scan_id}` outputs CycloneDX 1.6 `cryptographic-asset` components with `cryptoProperties` (`assetType`, `algorithmProperties`, `nistQuantumSecurityLevel`).

---

## 5. Assumptions, Limitations & Security Notes

1. **Simulated Enterprise**: The 5 TLS services (`legacy-web:9441`, `customer-api:9442`, `payments-core:9443`, `hr-records:9444`, `pqc-pilot:9445`) run locally as `openssl s_server` child processes.
2. **Self-Signed Internal CAs**: Public WebPKI CAs do not yet issue ML-DSA leaf certificates to browsers; therefore Quantum Guard recommends dual-certificate serving (`hybrid_mlkem_ecdsa` + `ML-DSA-65` dual-cert) for public endpoints and internal PQC CA (`ML-DSA-65`) leaves for internal services.
3. **Mosca Shelf-Life Parameters**: `years_to_crqc` (default 10 years) and `migration_years` (default 3 years) are configurable risk assumptions exposed as interactive sliders in the UI.
4. **Subprocess Benchmark Overhead**: When `liboqs-python` is not compiled in-process, PQC micro-benchmarks and `s_client` handshake benchmarks execute via the native OpenSSL 3.5+ CLI and include OS process creation overhead; use them for relative comparison.
5. **Key Vault Master Key**: Generated at `data/.master_key` (`chmod 600`) or read from `QG_MASTER_KEY`. Production deployments should wrap the master key in an FIPS 140-3 HSM or Cloud KMS.
