# ZKP Elections — Anonymous Verifiable Election Prototype

A research prototype of an anonymous, publicly verifiable election system built on **Bulletproofs** zero-knowledge proofs over the **secp256k1** elliptic curve. Votes are cryptographically committed so the tally is publicly verifiable without revealing any individual ballot.

---

## How It Works

### Cryptographic Protocol

1. **Pedersen Commitments** — Each vote value `v` is sealed as `Com(v; r) = g^v · h^r`, where `r` is a randomly chosen blinding factor. The commitment perfectly hides `v` while being computationally binding.

2. **Bulletproof Range Proofs** — A voter proves their committed value lies in `[0, 2^n)` without revealing it. Proof size is `2·log₂(n) + 9` group elements — logarithmic, with no trusted setup.

3. **Aggregate Range Proofs** — For multi-candidate ballots, `m` commitments can be proven valid in one aggregate proof, adding only `O(log m)` elements over a single proof.

4. **Fiat-Shamir Transform** — All proofs are made non-interactive by replacing verifier challenges with SHA-256 hashes of the proof transcript.

5. **Inner Product Argument** — The recursive logarithmic inner product argument (IPP) is the core of all Bulletproofs. Vector lengths are automatically zero-padded to the next power of 2.

6. **Verifiable Shuffle** — Before revealing the tally, the bulletin board shuffles the commitment list using a polynomial product equality argument (Schwartz-Zippel lemma), proving the output is a permutation of the input without linking individual votes.

7. **Batch Verification** — Multiple range proofs are verified simultaneously by drawing a random scalar `α` and combining checks into a single multi-exponentiation, significantly reducing verification cost at scale.

### Architecture

```
vote_producer  →  POST /vote  →  consumer_service
(CLI client)                     (Actix-web REST API)
```

| Component | Role |
|---|---|
| `crypto_primitives` | Deterministic generators, Pedersen commitments, Fiat-Shamir transcript |
| `bulletproofs_core` | Inner product argument, range proofs, aggregate proofs, shuffle, batch verification |
| `vote_producer` | CLI voter client — commits a vote and submits it with a range proof |
| `consumer_service` | Bulletin board REST API — ingests votes, verifies proofs, tallies results |
| `integration_tests` | End-to-end tests covering the full election pipeline |

---

## Prerequisites

- **Rust** ≥ 1.82 (edition 2021). Install via [rustup](https://rustup.rs):
  ```sh
  rustup update stable
  ```

---

## Building

```sh
cargo build --release
```

To build only a specific crate:
```sh
cargo build -p consumer_service --release
cargo build -p vote_producer --release
```

---

## Running Tests

Run all tests across every crate:
```sh
cargo test
```

Run tests for a specific crate:
```sh
cargo test -p crypto_primitives
cargo test -p bulletproofs_core
cargo test -p consumer_service
cargo test -p integration_tests
```

Run a specific test by name:
```sh
cargo test -p integration_tests multi_candidate_ballot
cargo test -p bulletproofs_core range_proof
```

Show test output (including `println!`):
```sh
cargo test -- --nocapture
```

### Test Coverage

| Crate | Tests |
|---|---|
| `crypto_primitives` | 13 — generators (hash-to-curve), Pedersen commitments, transcript |
| `bulletproofs_core` | 25 — IPP, range proofs, aggregate proofs, shuffle, batch verification |
| `consumer_service` | 3 — REST handler unit tests |
| `integration_tests` | 8 — full election pipeline, multi-candidate ballots, homomorphic tally, stress test (20 votes), edge cases |

---

## Running the Consumer Service

Start the bulletin board server:
```sh
cargo run --release -p consumer_service
```

Configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | TCP port to listen on |
| `RANGE_BITS` | `8` | Bit-length `n` for range proofs (vote values must be in `[0, 2^n)`) |

Example with custom settings:
```sh
PORT=9000 RANGE_BITS=16 cargo run --release -p consumer_service
```

### REST API

| Method | Path | Description |
|---|---|---|
| `POST` | `/vote` | Submit a `(commitment, proof)` vote payload |
| `GET` | `/status` | Election status (vote count, verification state) |
| `POST` | `/verify-batch` | Batch-verify all submitted proofs |
| `POST` | `/tally` | Finalize the election — runs the verifiable shuffle and reveals the tally |
| `GET` | `/ledger` | View the public ledger of all commitments |

#### Example: submit a vote

```json
POST /vote
{
  "commitment": "<hex-encoded SEC1 compressed point>",
  "proof": {
    "a_commit": "...",
    "s_commit": "...",
    "t1_commit": "...",
    "t2_commit": "...",
    "t_hat": "...",
    "tau_x": "...",
    "mu": "...",
    "ipp_proof": { "l_vec": [...], "r_vec": [...], "a": "...", "b": "..." },
    "n": 8
  }
}
```

All curve points are hex-encoded SEC1 compressed (33 bytes). All scalars are hex-encoded 32-byte big-endian.

---

## Running the Vote Producer

The vote producer is a CLI that generates a commitment and range proof for a given vote value and submits it to the consumer service.

```sh
cargo run --release -p vote_producer -- --vote <VALUE> [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--vote` | `-v` | *(required)* | Integer vote value |
| `--server` | `-s` | `http://127.0.0.1:8080` | Consumer service URL |
| `--bits` | `-b` | `8` | Range proof bit-length |
| `--dry-run` | | | Generate and print proof without submitting |

#### Examples

Cast a yes vote (value = 1):
```sh
cargo run --release -p vote_producer -- --vote 1
```

Cast a vote against a custom server:
```sh
cargo run --release -p vote_producer -- --vote 0 --server http://192.168.1.10:8080
```

Generate a proof without submitting (useful for testing):
```sh
cargo run --release -p vote_producer -- --vote 1 --dry-run
```

---

## Full Election Demo

In one terminal, start the consumer service:
```sh
cargo run --release -p consumer_service
```

In another terminal, submit several votes:
```sh
cargo run --release -p vote_producer -- --vote 1
cargo run --release -p vote_producer -- --vote 0
cargo run --release -p vote_producer -- --vote 1
```

Check the ledger:
```sh
curl http://127.0.0.1:8080/ledger
```

Batch-verify all submitted proofs:
```sh
curl -X POST http://127.0.0.1:8080/verify-batch
```

Finalize and tally (runs the verifiable shuffle):
```sh
curl -X POST http://127.0.0.1:8080/tally
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| **Vote secrecy** | Pedersen commitment perfectly hides the vote value |
| **Vote validity** | Bulletproof range proof — vote ∈ [0, 2^n) without revealing it |
| **Anonymity** | Verifiable shuffle permutes the commitment list before tallying |
| **Public verifiability** | All proofs are non-interactive (Fiat-Shamir) and publicly checkable |
| **No trusted setup** | Generators derived via hash-to-curve (RFC 9380 `hash_to_field`) |
| **Binding** | Computational binding under the discrete log assumption on secp256k1 |

> **Note:** This is a research prototype. It has not undergone a security audit. Do not use it in production.

---

## Project Structure

```
zkp-elections-anon/
├── Cargo.toml                   # Workspace root
├── crypto_primitives/
│   └── src/
│       ├── generators.rs        # Deterministic Bulletproof generator vectors
│       ├── pedersen.rs          # Pedersen commitments + multi-scalar mul
│       └── transcript.rs        # Fiat-Shamir transcript (SHA-256)
├── bulletproofs_core/
│   └── src/
│       ├── inner_product.rs     # Recursive inner product argument
│       ├── range_proof.rs       # Single-value Bulletproof range proof
│       ├── aggregate.rs         # Aggregate range proofs for m values
│       ├── shuffle.rs           # Verifiable shuffle (polynomial product)
│       ├── batch.rs             # Batch verification of range proofs
│       └── util.rs              # Scalar/vector arithmetic helpers
├── vote_producer/
│   └── src/main.rs              # CLI voter client
├── consumer_service/
│   └── src/main.rs              # Actix-web bulletin board / verifier
└── integration_tests/
    └── src/lib.rs               # End-to-end election pipeline tests
```
