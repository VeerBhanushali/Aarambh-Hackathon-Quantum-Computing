# Learn PS07 from Zero

A beginner's guide to the problem statement and to how Quantum Guard solves it.
Read the parts in order: each one builds on the one before.

---

## Part 1 — The basics: what cryptography does

When you open your bank's website, three jobs happen:

| Job | Question it answers | Everyday comparison |
|---|---|---|
| **Encryption** | Can anyone else read this? | A locked box |
| **Key exchange** | How do two strangers agree on the same key without meeting? | Agreeing on a secret code while someone listens |
| **Signature** | Is this really my bank, and was nothing changed? | A signature plus a tamper-proof seal |

There are two families of algorithms:

- **Symmetric** (AES): one shared key locks and unlocks. Fast. Used for the actual data.
- **Asymmetric / public-key** (RSA, ECC, X25519, ECDSA): a **public key** anyone can see and a **private key** you keep secret. Used for key exchange and signatures.

A normal secure connection (**TLS**, the "s" in https) works like this:

1. **Handshake:** use public-key crypto to agree on a secret key (key exchange) and prove the server is real (signature plus **certificate**).
2. **Data:** use that key with AES to encrypt everything.

A **certificate** is an ID card for a server: "this public key belongs to bank.com", signed by a trusted
**Certificate Authority (CA)**. The chain of who signed whom is called **PKI** (Public Key Infrastructure).

---

## Part 2 — The problem: quantum computers

RSA and ECC are safe because certain maths problems take normal computers millions of years. A large future
quantum computer running **Shor's algorithm** could solve them in hours. Then:

- **Key exchange is broken**, so recorded traffic can be decrypted.
- **Signatures are broken**, so someone could fake a bank's identity.

**Symmetric crypto (AES) is mostly fine.** The quantum attack on it (**Grover's algorithm**) only halves its
strength. AES-256 stays strong; AES-128 gets a "prefer 256" note.

No such quantum computer exists yet. People call the future one a **CRQC** (cryptographically relevant quantum
computer). So why act now?

### Harvest now, decrypt later (HNDL)

An attacker records your encrypted traffic **today** and stores it. In about 10 years, when the quantum computer
exists, they decrypt it. If that data must stay secret for 25 years (medical or HR records), it is **already at risk**.

This is why **key exchange must be fixed first**. Signatures can't be attacked this way: faking a signature
later doesn't help with a conversation that already ended.

### Mosca's rule (when are you in trouble?)

**X + Y > Z** means you're already late.

- **X** = how many years the data must stay secret
- **Y** = how many years migration takes
- **Z** = years until a quantum computer exists

Example: HR records → 25 + 3 = 28 > 10, so urgent.

---

## Part 3 — The solution: post-quantum cryptography (PQC)

New algorithms built on maths that quantum computers can't solve easily. NIST (the US standards body)
published them in **August 2024**:

| Name | Standard | Replaces | Used for |
|---|---|---|---|
| **ML-KEM** (was "Kyber") | FIPS 203 | RSA/ECDH key exchange | Agreeing on keys |
| **ML-DSA** (was "Dilithium") | FIPS 204 | RSA/ECDSA signatures | Signatures and certificates |
| **SLH-DSA** (was "SPHINCS+") | FIPS 205 | Signatures | Very conservative, hash-based; slow and big, so for long-lived root keys |

The numbers after the names (ML-KEM-**768**, ML-DSA-**65**) are strength levels. Bigger means stronger and slower.

**The trade-off (from our benchmarks):** PQC is **fast** but **big**.

- ML-KEM is even faster than RSA.
- ML-DSA signatures are ~3,300 bytes vs 72 bytes for ECDSA.

### Deadlines (NIST IR 8547)

- **After 2030:** RSA and ECC **deprecated** (should stop using)
- **After 2035:** **disallowed**

### Hybrid: don't bet on one horse

PQC is new; what if a flaw is found? **Hybrid** = do classical **and** PQC together and combine both secrets.
An attacker must break **both**. In TLS this is the group **X25519MLKEM768** (X25519 + ML-KEM-768).
OpenSSL 3.5 (April 2025) supports it, which is why the project needs OpenSSL 3.5.

### Why public websites keep old certificates

Public CAs (the ones browsers trust) don't issue ML-DSA certificates yet. So the trick is **dual certificates**:
the server holds both, gives old clients the ECDSA one and new clients the ML-DSA one.

---

## Part 4 — What PS07 asks, and what our project does

The problem statement says: *help an organisation find its quantum-vulnerable crypto, measure the risk,
and migrate safely.* Seven use cases:

| # | What PS07 wants | What it means | Where in the project | What we show |
|---|---|---|---|---|
| 1 | **Discovery** | Find all crypto in use | `app/discovery/` | Scan 5 servers + code + certificates → 46 assets; download a **CBOM** |
| 2 | **Vulnerability assessment** | How bad is each one? | `app/risk.py` | Score 0–100, red/amber/green, HNDL "urgent" badge |
| 3 | **Migration** | What to change, in what order | `app/planner.py` | 3 waves → Apply → rescan → readiness goes up |
| 4 | **Hybrid encryption** | Classical + PQC together | `app/crypto_lab/` | Encrypt a message both ways; tamper test; 3 policy tests |
| 5 | **Benchmarking** | Is PQC slow? | `app/benchmark.py` | Speed and size charts |
| 6 | **Certificate migration** | Move PKI to PQC | `app/pki.py` | Two CAs; dual-cert demo |
| 7 | **Dashboard** | Show it all | `app/static/` | Web page with every tab plus the Guided Demo |

Extra words you'll hear:

- **CBOM** (Cryptographic Bill of Materials): a list of every crypto item, like an ingredients label.
  Ours uses the standard **CycloneDX** format.
- **Crypto-agility:** designing systems so you can swap algorithms easily later.
- **Key vault:** where private keys are stored. Ours encrypts them with AES-256-GCM so they're never sitting
  in plaintext.

---

## Part 5 — How the project works

```
Browser dashboard  ──>  FastAPI (Python web server)  ──>  modules
                                                     ├─ runs `openssl` commands (does the real crypto)
                                                     └─ saves results in SQLite (a small database file)
```

- **"Simulated enterprise"** = 5 fake company servers running on your laptop (ports 9441–9445), each configured
  like a real company would be: one old (TLS 1.2 + RSA), some modern-classical, one already hybrid.
- **Scan** = connect to each server like a browser would (`openssl s_client`) and note what it used.
- **Apply** = restart those servers with hybrid settings, then scan again to prove it worked.
- **Rule of the project:** no homemade crypto; only OpenSSL and the Python `cryptography` library.
  Every number comes from a real run.

---

## Part 6 — The order of the demo

1. Start the enterprise
2. Scan "before"
3. See the risks
4. Make the plan
5. Apply
6. Scan "after"
7. Hybrid lab
8. Dual certificates
9. Benchmarks

The **Run Guided Demo** button does all of this automatically.

---

## Part 7 — Likely judge questions, with short answers

- **"Why fix key exchange first?"** Harvest now, decrypt later: recorded traffic can be decrypted later, while
  signatures can't be broken after the fact.
- **"Why hybrid and not pure PQC?"** Safety if either algorithm has a flaw, and compatibility with old clients.
  NIST said the 2035 ban wasn't meant to apply to hybrids.
- **"Why only 48% readiness after migration?"** The remaining items are source-code changes; an automatic tool
  shouldn't rewrite code. Network readiness reached 87%.
- **"Is PQC slow?"** Key exchange: no, faster than RSA. Signatures: slower and much bigger.
  The real cost is bytes.
- **"Is it quantum-proof?"** Say **"quantum-resistant"**. Nothing is proven unbreakable.
- **"Is this real?"** The algorithms, handshakes and measurements are real. The company is simulated.

---

## Learn it hands-on (about 1 hour)

1. Run the app (see [`NEXT_STEPS.md`](../NEXT_STEPS.md), Task 1) and click **Run Guided Demo**.
2. Open each tab and match it to the table in Part 4.
3. In **Risk**, move the "years to quantum" slider and watch the urgent badges change. That's Mosca's rule.
4. In **Hybrid Lab**, switch Classical/Hybrid and compare sizes; tick **Tamper** to see decryption refused.
5. Read each slide's speaker notes in the deck ([`docs/deck/slides/`](deck/slides/)); they're written to be said aloud.
