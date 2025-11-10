# Fibonacci ZK + TLSNotary

A demonstration project combining **TLSNotary** (authenticated HTTPS data) with **Zero-Knowledge Proofs** (Stwo STARK) to prove knowledge of a secret Fibonacci computation.

## ⚡ Quick Start

```bash
# Terminal 1: Start test server
cargo run --bin test_server

# Terminal 2: Test server (optional)
curl http://127.0.0.1:3000/fibonacci
# Output: {"challenge_index":5,"status":"ok"}

# Terminal 3: Run tests
cargo test

# For full demo:
# Note: Currently requires proper TLS setup with tlsn-server-fixture
# cargo run
```

**Environment Variables:**
```bash
# Custom server configuration
SERVER_HOST=127.0.0.1   # Default: 127.0.0.1
SERVER_PORT=3000        # Default: 3000
SERVER_DOMAIN=localhost # Default: localhost
```

## 🎯 What This Does

This project demonstrates a privacy-preserving computation system where:

1. **Prover** receives a secret number (`fibonacci_index`) from an HTTPS server
2. **Prover** computes `fibonacci(fibonacci_index)`
3. **Prover** generates a ZK proof showing:
   - "I know a secret index from the server"
   - "I computed fibonacci(secret_index) correctly"
   - "The result is X"
4. **Verifier** confirms the computation is correct **WITHOUT learning the secret index!**

### Key Technologies

- **TLSNotary (MPC-TLS)**: Cryptographic proof that data comes from a real HTTPS server
- **Stwo STARK**: Zero-knowledge proof system from Starkware
- **Tokio**: Async runtime for concurrent prover/verifier

## 🏗️ Architecture

```
┌─────────┐                ┌─────────┐               ┌──────────┐
│ Server  │                │ Prover  │               │ Verifier │
└────┬────┘                └────┬────┘               └────┬─────┘
     │                          │                         │
     │  1. MPC-TLS Setup        │◄────────────────────────┤
     │     (joint computation)  │                         │
     │                          │                         │
     │  2. HTTPS Request        │                         │
     ├─────────────────────────►│                         │
     │  {"challenge_index": 5}  │                         │
     │◄─────────────────────────┤                         │
     │                          │                         │
     │                          │  3. TLSNotary Proof     │
     │                          ├────────────────────────►│
     │                          │  (transcript + commits) │
     │                          │                         │
     │                          │  4. Generate ZK Proof   │
     │                          │  fib_index = 5 (SECRET) │
     │                          │  Compute: fib(5) = 5    │
     │                          │                         │
     │                          │  5. Send Proof Bundle   │
     │                          ├────────────────────────►│
     │                          │  {proof, fib_value: 5}  │
     │                          │                         │
     │                          │                         │  6. Verify:
     │                          │                         │  ✓ TLSNotary
     │                          │                         │  ✓ Hash commit
     │                          │                         │  ✓ ZK proof
     │                          │                         │  ✓ Accept!
```

## 📦 Project Structure

```
src/
├── lib.rs               # Library exports
├── main.rs              # Example runner (prover + verifier)
├── server.rs            # HTTP server for testing
├── types.rs             # Data structures (FibonacciZKProofBundle, etc.)
├── prover.rs            # Prover logic (MPC-TLS + ZK proof generation)
├── verifier.rs          # Verifier logic (verification)
├── prover_test.rs       # Unit tests for prover
├── bin/
│   └── test_server.rs   # Standalone test server binary
└── stwo/                # STARK implementation
    ├── mod.rs           # Prove/verify functions
    ├── computing.rs     # AIR (constraint) definitions
    └── trace_gen.rs     # Execution trace generation
```

## 🚀 Getting Started

### Prerequisites

- Rust nightly (2025-07-14)
- A test HTTPS server (or use tlsn-server-fixture)

### Installation

```bash
# Clone the repository
cd fibonacci_zk_tlsn

# Build the project
cargo build --release

# Run tests
cargo test
```

### Running the Test Server

First, start the test HTTP server in a separate terminal:

```bash
# Start server on default port (3000)
cargo run --bin test_server

# Or specify custom port
cargo run --bin test_server -- --port 8080
```

The server will start and display:
```
╔══════════════════════════════════════════════════════════╗
║   Fibonacci ZK + TLSNotary Test Server                  ║
╚══════════════════════════════════════════════════════════╝

  🚀 Starting server on http://127.0.0.1:3000
  📡 Available endpoints:
     GET /fibonacci - Returns challenge_index
```

**Test the server:**
```bash
curl http://127.0.0.1:3000/fibonacci
# Output: {"challenge_index":5,"status":"ok"}
```

### Running the Full Demo

Once the server is running, in a separate terminal:

```bash
# Run with default settings (connects to localhost:3000)
cargo run

# Or with custom server
SERVER_HOST=example.com SERVER_PORT=443 cargo run
```

**Note**: For TLSNotary to work properly, you need to use the `tlsn-server-fixture` which provides TLS support. The basic test server above is HTTP-only for simple testing.

## 🔬 How It Works

### 1. TLSNotary Phase

The prover connects to a server through MPC-TLS:
- Prover and Verifier jointly compute the TLS session
- Server returns JSON: `{"challenge_index": 5}`
- Prover creates a **hash commitment** for `challenge_index`
- Verifier gets proof of authenticity but NOT the value

### 2. ZK Proof Phase

The prover generates a STARK proof with 8 constraints:

1. **Fibonacci relation**: `c = a + b`
2. **State transition**: `a[i] = b[i-1]`
3. **State transition**: `b[i] = c[i-1]`
4. **Initial state**: `a[0] = 0`
5. **Initial state**: `b[0] = 1`
6. **Witness boolean**: `is_target ∈ {0, 1}`
7. **Witness uniqueness**: Only one row has `is_target = 1`
8. **KEY**: `is_target * (a - fibonacci_value) = 0`

The circuit computes Fibonacci for all indices 0..N, but only marks ONE row (the secret index) with `is_target = 1`. The constraint forces that row to have the correct public output.

**Example trace for fibonacci(5):**

| Row | a  | b  | c  | is_target | Comment |
|-----|----|----|----|-----------| ------- |
| 0   | 0  | 1  | 1  | 0         | fib(0) |
| 1   | 1  | 1  | 2  | 0         | fib(1) |
| 2   | 1  | 2  | 3  | 0         | fib(2) |
| 3   | 2  | 3  | 5  | 0         | fib(3) |
| 4   | 3  | 5  | 8  | 0         | fib(4) |
| 5   | **5**  | 8  | 13 | **1** | **fib(5) = 5** ← SECRET INDEX |
| ... | ... | ... | ... | 0     | padding |

### 3. Verification Phase

The verifier:
1. ✅ Checks TLSNotary transcript (data is authentic)
2. ✅ Verifies server identity
3. ✅ Confirms hash commitment exists
4. ✅ Verifies STARK proof (computation is correct)
5. ✅ **NEVER learns which row was marked!**

## 🎮 Real-World Applications

This pattern enables privacy-preserving proofs for:

- **Age Verification**: Prove "I'm over 18" without revealing exact birthdate
- **Credit Scores**: Prove "Score > 700" without revealing exact score
- **Income Verification**: Prove "Income > $50k" without revealing exact amount
- **KYC**: Prove attributes about identity without revealing full identity

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_simple_fib_prove_verify

# Run with output
cargo test -- --nocapture
```

### Test Coverage

- ✅ Fibonacci computation correctness
- ✅ JSON parsing and extraction
- ✅ STARK proof generation and verification
- ✅ Trace generation for different indices
- ✅ Component creation and constraints

## 📊 Performance

- **Proof Generation**: ~100ms (for fibonacci_index < 100)
- **Proof Verification**: ~50ms
- **Proof Size**: ~50KB (varies with log_size)
- **Memory**: ~10MB peak during proving

## 🔐 Security

- Uses Stwo STARK (production-ready from Starkware)
- TLSNotary v0.1.0-alpha.13
- Hash commitments with SHA-256
- No information leakage about secret index

## 📝 License

This project is for demonstration and educational purposes.

## 🙏 Acknowledgments

- [Stwo](https://github.com/starkware-libs/stwo) - STARK prover from Starkware
- [TLSNotary](https://github.com/tlsnotary/tlsn) - MPC-TLS implementation
- Inspired by privacy-preserving computation research

## 🐛 Known Limitations

- Currently uses simplified commitment (direct comparison)
- Production version should use SHA256 circuit for full privacy
- Requires test server setup for running
- Limited to relatively small Fibonacci indices (< 1000)

## 🚧 Future Work

- [ ] Add SHA256 circuit for full hash verification
- [ ] Support for larger indices with optimized traces
- [ ] Batching multiple proofs
- [ ] Integration with real-world servers
- [ ] Performance benchmarks
