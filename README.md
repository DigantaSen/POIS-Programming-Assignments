# CS8.401 POIS — Minicrypt Clique Explorer

Interactive implementation of the Minicrypt reduction chain: **OWF → PRG → PRF → ENC** (and reverse directions), with a React webapp that makes every reduction visual, interactive, and traceable with real data.

## Completed Assignments

### PA#0 — Minicrypt Reduction Explorer (Webapp Scaffold)

**Interactive React webapp** with a three-tier layout:

- **Foundation toggle** — switch between AES-128 (PRP) and DLP (OWP) as the concrete starting point.
- **Column 1 (Build)** — chain from Foundation → Source Primitive A, showing every intermediate hex value.
- **Column 2 (Reduce)** — reduce Source A → Target B step-by-step; Column 2 consumes Column 1's oracle as a black box.
- **Proof summary panel** — collapsible bottom panel showing the full formal security chain (theorem, security claim, PA source).
- **Bidirectional mode** — Forward (A → B) / Backward (B → A) toggle swaps columns and attempts the reverse reduction.
- **Stub support** — unimplemented primitives display "Not implemented yet (due: PAxx)" with the correct assignment number.

### PA#1 — One-Way Functions & Pseudorandom Generators

**OWF (DLP-based):**
- `f(x) = g^x mod p` in a prime-order subgroup (safe prime p ≈ 2³¹, generator g = 4).
- `evaluate(x)` — compute the OWF.
- `verify_hardness(trials)` — empirically confirm random inversion fails (success ≈ 1/q ≈ 10⁻¹⁰).

**PRG (Håstad–Impagliazzo–Levin–Luby):**
- Iterative hard-core-bit construction: `G(x₀) = b(x₀) ‖ b(x₁) ‖ … ‖ b(xₗ)` where `xᵢ₊₁ = f(xᵢ)`.
- Hard-core bit via Blake2s hash (LSB).
- Interface: `seed(s)`, `next_bits(n)` — black-box for PA#2.

**OWF from PRG (backward direction, PA#1b):**
- `f(s) = G(s)` is a OWF: if PRG output were easy to invert, the inverter would recover seed preimages, contradicting the one-wayness of `f` used in the construction. The PRG stretches n bits to n+ℓ bits; an adversary given G(s) must search a space that grows exponentially with ℓ.
- `verify_prg_as_owf()` — brute-force bounded-search demo confirms inversion fails.

**Statistical test suite (NIST SP 800-22):**
- Frequency (monobit), Runs, Serial (2-bit) — all report p-values, threshold α = 0.01.

**Webapp demo:** hex seed input, output length slider (8–256 bytes), live G(s) output, bit-ratio bar, "▶ Run Tests" button.

**Toy parameters:** 64-bit seed, DLP group order ≈ 2³⁰. All operations complete in < 1 second.

### PA#2 — Pseudorandom Functions via GGM Tree

**GGM PRF (forward direction, PA#2a):**
- Given length-doubling PRG G, split `G(s) = G₀(s) ‖ G₁(s)`.
- `F_k(b₁ … bₙ) = G_bₙ(… G_b₁(k) …)` — root-to-leaf tree traversal.
- Cost: n PRG calls per query (one root-to-leaf path).

**PRG from PRF (backward direction, PA#2b):**
- `G(s) = F_s(0ⁿ) ‖ F_s(1ⁿ)` — length-doubling PRG from PRF.
- Verified via the same NIST statistical tests as PA#1 (frequency, runs, serial — all PASS).

**AES-128 plug-in PRF:**
- `F_k(x) = AES_k(x)` via the `cryptography` package (the one allowed external primitive).
- Same `F(k, x)` interface; substituting AES for GGM produces identical downstream behaviour.

**Distinguishing game:**
- Queries PRF and a truly random oracle on q=100 random inputs.
- Compares 1-ratio of output bits. Threshold: `|δ| < 0.05` → INDISTINGUISHABLE.

**Interface:** `F(k, x)` drop-in for PA#3, PA#4, PA#5. Accepts int, bytes, or hex string.

**Webapp demo:** key hex input, depth slider (4–8), clickable bit-toggle query, SVG GGM tree (full tree for n≤4, path-only for n>4), avalanche demo (1-bit flip → uncorrelated output), PRG-from-PRF preview.

### PA#3 — CPA-Secure Symmetric Encryption

**Enc-then-PRF construction:**
- `Enc(k, m) = (r, F_k(r) ⊕ m₀ ‖ F_k(r+1) ⊕ m₁ ‖ …)` with fresh random 8-bit nonce r.
- Counter mode: block i uses keystream `F_k((r + i) mod 256)`.
- PKCS7 padding for non-block-aligned messages.
- Block size: 4 bytes (lower 32 bits of GGM PRF output).

**IND-CPA security game:**
- Advantage = `2 · |Pr[b'=b] − ½|` (ranges 0 to 1.0).
- 50-round simulation with random adversary: advantage ≈ 0 (≤ 0.1 expected).
- Smart adversary with nonce reuse: advantage = **1.0** (full break).

**Broken variant (nonce reuse / deterministic encryption):**
- Fixed nonce → identical ciphertexts for identical messages. Adversary trivially detects which message was encrypted.
- XOR attack: `ct₀ ⊕ ct₁ = m₀ ⊕ m₁` (keystream cancels when nonce is reused).
- Contrast: fresh nonces → same message produces different ciphertexts every time.

**Security argument:**
- `Adv_IND-CPA(A) ≤ Adv_PRF(D)`: any IND-CPA adversary A yields a PRF distinguisher D with at least the same advantage. Since PA#2's GGM PRF is secure (PRG ⇒ PRF), the advantage is negligible.

**Interface:** `Enc(k, m) → (r, c)` and `Dec(k, r, c) → m` — drop-in for PA#6 (authenticated encryption).

**Webapp demo:** IND-CPA game (player acts as adversary), "Start Round →" to get challenge ciphertext, guess which message was encrypted, animated advantage bar (0 → 1.0 scale), "Reuse Nonce" toggle (green=secure / red=broken), nonce-reuse XOR attack display, 4 theory cards.

## Reduction Chain Status

```
OWP ──→ OWF ──→ PRG ──→ PRF ──→ ENC     (all implemented ✓)
                              ──→ PRP     (due: PA04)
                              ──→ MAC     (due: PA05)
                              ──→ CRHF    (due: PA08)
```

Reverse edges (ENC→PRF, PRF→PRG via PRG-from-PRF, PRP→PRF via switching lemma) are modelled in the routing table and used in backward mode.

## Setup After Unzipping

### Prerequisites

- **Python 3.10+** ([python.org](https://www.python.org/downloads/))
- **Node.js 18+** with npm ([nodejs.org](https://nodejs.org/))
- **Git Bash** (Windows) — for running `.sh` scripts, comes bundled with [Git for Windows](https://git-scm.com/download/win)

### Step-by-step (Windows)

```powershell
# 1. Unzip — right-click the zip → Extract All, or:
Expand-Archive -Path .\Assignment1_Diganta_*.zip -DestinationPath .

# 2. Navigate into the project
cd Assignment1

# 3. Create Python virtual environment + install package
python -m venv .venv
.venv\Scripts\activate
pip install -e .
# This also installs the 'cryptography' package (AES plug-in dependency)

# 4. Verify Python backend works
python -c "from pois.assignments.pa01 import PA01; print(PA01().run_demo())"
python -c "from pois.assignments.pa02 import PA02; print(PA02().run_demo())"
python -c "from pois.assignments.pa03 import PA03; print(PA03().run_demo())"

# 5. Install webapp dependencies + start dev server
cd webapp
npm install
npm run dev
# Opens at http://localhost:5173/
```

### Step-by-step (macOS / Linux)

```bash
# 1. Unzip
unzip Assignment1_Diganta_*.zip
cd Assignment1

# 2. Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 3. Verify
python -c "from pois.assignments.pa01 import PA01; print(PA01().run_demo())"

# 4. Webapp
cd webapp && npm install && npm run dev
```

### CLI workflow

```bash
python -m pois.cli status                              # see task status
python -m pois.cli next --member Kushal                # claim next task
python -m pois.cli complete --member Kushal --task PA04 # mark done
```

## Team Workflow (Sequential)

### Assignment Ownership (5 group members)

| Member   | Assignments |
|----------|-------------|
| Diganta  | PA00, PA01, PA02, PA03 |
| Kushal   | PA04, PA05, PA06, PA07 |
| Nilkanta | PA08, PA09, PA10, PA11 |
| Rohit    | PA12, PA13, PA14, PA15 |
| Srinjoy  | PA16, PA17, PA18, PA19, PA20 |

## Directory Map

```
src/pois/assignments/
  pa01.py    — DLP OWF + HILL PRG + NIST tests + backward OWF-from-PRG
  pa02.py    — GGM PRF + AES plug-in + PRG-from-PRF + distinguishing game
  pa03.py    — CPA-secure Enc/Dec + IND-CPA game + nonce-reuse attack
  pa04–20.py — stubs (raise NotImplementedError)
  base.py    — AssignmentModule interface

webapp/src/
  App.tsx         — tab navigation + PA#0 Reduction Explorer
  Pa01Panel.tsx   — OWF & PRG interactive demo
  Pa02Panel.tsx   — GGM tree visualizer
  Pa03Panel.tsx   — IND-CPA game + nonce-reuse demo
  prg.ts          — TypeScript PRG engine (mirrors pa01.py)
  ggm.ts          — TypeScript GGM tree (mirrors pa02.py)
  enc.ts          — TypeScript Enc/Dec (mirrors pa03.py)
  routing.ts      — reduction graph + BFS path finder
  foundations.ts  — AES/DLP foundation modules
  domain.ts       — shared types
  index.css       — full design system

workflow/tasks.json — dependency graph + ownership map
```

## Rules

- No external cryptographic library substitutions in the primitive chain (AES-128 is the one allowed exception).
- Every PA module inherits `AssignmentModule` with `info()`, `deliverables()`, and `run_demo()`.
- Unimplemented PAs raise `NotImplementedError` by default.
- Webapp Column 2 must consume Column 1's oracle as a black box — no direct foundation calls.
