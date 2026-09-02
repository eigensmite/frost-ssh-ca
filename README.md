# frost-ssh-ca

**A distributed SSH certificate authority whose master signing key never exists in one place.**

`frost-ssh-ca` replaces the single Ed25519 private key at the heart of an SSH certificate
authority with a *t*-of-*n* threshold key generated and held across `n` independent signer
nodes. No node — signer or coordinator — ever holds, reconstructs, or observes the complete
CA private key, at generation, at signing, or during refresh.

The aggregate output is an ordinary Ed25519 Schnorr signature. From OpenSSH's perspective
the group public key is indistinguishable from a normal CA key, so it drops straight into a
`TrustedUserCAKeys` file with **no modification to the SSH protocol, client, or server**.

> **Status: research prototype.** This is capstone work, not audited software. It has known
> implementation-maturity gaps (see [Limitations](#limitations)) and should not be used to
> protect a production certificate authority.

---

## The problem

An SSH CA is elegant until you look at where the trust sits. One private key signs every
certificate; every host in the fleet is configured to trust it. That key is:

- **A total-compromise target.** Steal it and you can mint valid credentials for any user or
  host, indefinitely, without detection. The blast radius is the entire infrastructure.
- **A total-loss target.** Destroy it and every certificate must be reissued and every server
  reconfigured to trust a new CA.

The conventional answer is an HSM, which is expensive, is itself a single physical point of
failure unless replicated, introduces third-party and jurisdictional trust when cloud-managed,
and has a real-world track record of API-level and hypervisor-level compromise.

Threshold cryptography offers a different answer: don't protect the key, don't create it.
Under a *t*-of-*n* distributed key generation, an adversary must compromise `t` nodes
*simultaneously* to sign anything. Compromising fewer than `t` yields nothing at all.

## Why FROST

[FROST](https://eprint.iacr.org/2020/852) (Flexible Round-Optimized Schnorr Threshold
signatures), standardized as [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591), is a
two-round threshold Schnorr protocol with a distributed key generation ceremony built on
Pedersen DKG with Feldman verifiable secret sharing.

The decisive property for this use case is the ciphersuite. FROST's default is
`FROST(Ed25519, SHA-512)` — the exact curve OpenSSH has used for its CA key format since
OpenSSH 9.5. Prior threshold-CA work doesn't have this: COCA and ESKM produce threshold-RSA
signatures over X.509 assumptions, and the two-party MPC approach of Jayaraman et al. is
locked to secp192k1 and to `n = 2`, at roughly 410–819 GiB of circuit transfer *per signature*.
FROST needs two network round trips and kilobytes.

## What this project adds on top of FROST

Bare FROST is a signing-ceremony specification. It explicitly treats share storage, signer
availability, refresh scheduling, and channel authentication as out of scope. This project
supplies each of those:

| Mechanism | What it closes |
| --- | --- |
| **ROAST robustness wrapper** | Bare FROST aborts with no output if a single signer stalls or misbehaves. The coordinator holds multiple candidate sessions in escrow, drops non-responsive or corrupting signers, and forms a session from whichever `t` prove reliable — guaranteed to terminate within `n − t + 1` sessions. |
| **Mutual TLS on the coordinator–signer channel** | RFC 9591 §7 and Bellare et al. require an authenticated channel to reach the TS-UF-4 tier. Every signer and the coordinator hold an RSA-2048 identity keypair and authenticate both directions. |
| **Identity-bound commitments** | A malicious coordinator could otherwise substitute or replay commitments across sessions, or present signers with a message different from the one that solicited their commitments. Each commitment carries a signer-issued signature over `commitment ‖ message`, so it is cryptographically valid only for the message it was generated against. This applies [FROST2+](https://eprint.iacr.org/2026/075)'s identity-binding principle inside a FROST1 system, without requiring an audited FROST2+ implementation. |
| **OAEP-RSA-encrypted Round 2 secrets** | DKG and refresh Round 2 messages are per-recipient evaluations of each signer's secret polynomial, and they are routed *through* the coordinator. Sent in the clear, a curious coordinator could collate them and reconstruct the group secret directly. Plain RSA is insufficient here — lacking semantic security, it permits an all-values comparison attack — so Round 2 payloads are encrypted under the recipient's dedicated OAEP keypair, which is kept separate from the identity keypair to avoid cross-protocol oracle interactions. |
| **Proactive share refresh** | A patient mobile adversary can accumulate shares across successive sub-threshold intrusions until it holds `t`. Refresh runs a DKG in which every signer's polynomial has a zero constant term, so `s(0)` — the group secret — is unchanged while every individual share becomes a new, unrelated value. Certificates signed before and after a refresh are valid under the same CA key. Crucially, no node reconstructs the secret to do this: an earlier trusted-distributor design that collected shares at the coordinator was scrapped precisely because it reintroduced the single point of trust the architecture exists to remove. |

## Architecture

```
                       CA Operator
                  (pubkey, principal, serial, validity)
                              │
                              ▼
                     ┌──────────────────┐
                     │   Coordinator    │   mode: DKG | SIGN | REFRESH
                     │  ROAST sessions  │   routes and aggregates only —
                     │  aggregate/mint  │   holds no long-term key share
                     └──────────────────┘
                     ╱        │         ╲
                 mTLS       mTLS        mTLS
                 ╱            │            ╲
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │ Signer 1 │   │ Signer 2 │ … │ Signer n │
        └──────────┘   └──────────┘   └──────────┘
              │              │              │
      shares/signer_1  shares/signer_2  shares/signer_n
           .keypkg         .keypkg          .keypkg
```

The coordinator is **semi-trusted**. It decides what gets proposed for signing, and it can
stall or disrupt a ceremony — but it structurally cannot learn a signer's share or the group
secret, and it cannot retarget an already-solicited signature at a different message. Signers
persist their own `KeyPackage` locally; the secret share is never transmitted.

Threat model in full: no single node is trusted with the reconstructed key at any point
(ruling out trusted-dealer setup); a mobile adversary may compromise different nodes over
time; up to `t − 1` signers may be offline, silent, or actively returning invalid shares
without preventing a successful signature.

## Build

Requires a Rust toolchain (Cargo), a C compiler, and OpenSSL.

```sh
cd frost_signer_core && cargo build && cd ..
make
./gen_tls_certs.sh          # regenerate mTLS + OAEP keypairs if needed
```

The Rust crate `frost_signer_core` wraps the Zcash Foundation's audited `frost-ed25519`
implementation and provides DKG rounds 1–2, refresh rounds 1–2, commitment and nonce
generation, signature-share generation, and FROST-public-key-package → OpenSSH Ed25519
conversion. The C layer handles networking, the coordinator/signer command interface, and
ROAST session management.

## Usage

**1. Run a DKG ceremony** to create the CA key. Start the coordinator, then `n` signers:

```sh
./frost_coordinator dkg --t <t> --n <n>
for i in $(seq 1 <n>); do ./frost_signer $i <t> <n> & done
```

The group public key is written to `pub_key_pkg.hex`; each signer persists its own share to
`shares/signer_<id>.keypkg`.

**2. Export the CA public key** in OpenSSH format:

```sh
cat ./pub_key_pkg.hex \
  | ./frost_signer_core/target/debug/frost_signer_core pubkey > ca.pub
```

**3. Install it** on any host that should trust the CA:

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ca.pub
```

**4. Issue a certificate.** Place the user's `user_key.pub` in the working directory (or pass
it explicitly) and specify a principal:

```sh
./frost_coordinator sign --t <t> --n <n> --principal alice
for i in $(seq 1 <n>); do ./frost_signer $i <t> <n> & done
```

The signed certificate is written to `./output/user_key-cert.pub`. Inspect it with
`ssh-keygen -L -f ./output/user_key-cert.pub`.

**5. Refresh shares** at will, without changing the CA public key:

```sh
./frost_coordinator refresh --t <t> --n <n>
for i in $(seq 1 <n>); do ./frost_signer $i <t> <n> & done
```

### Test and benchmark flags

| Flag | Effect |
| --- | --- |
| `--mass-mint <count>` | Issue `count` certificates sequentially, incrementing the serial number. |
| `--fault tbs-replace` | Coordinator substitutes the to-be-signed message after soliciting commitments. Signers should detect and refuse. |
| `--fault bad-share` | Signer returns a corrupted signature share. The coordinator should identify, blacklist, and re-form the session. |

## Results

**Throughput** — 1,000 unique, valid certificates under a 16-of-16 configuration on a
Ryzen 7800X3D:

| Topology | Wall clock | Rate | Avg/cert |
| --- | --- | --- | --- |
| Single host (loopback) | ≈21 min | ≈47.6 certs/min | ≈1.26 s |
| Two hosts over local Wi-Fi | ≈27 min | ≈37.0 certs/min | ≈1.62 s |

Over 99% of the loopback-to-LAN gap is accounted for by additional time in the coordinator's
`select()` call, isolating the ~29% overhead to network waiting rather than any other
subsystem. Commitment precomputation made no significant difference in either topology at
this scale. Every certificate in these runs was verified after the fact for a matching CA key,
matching principal, and distinct serial.

**Fault tolerance** — three injection scenarios:

- *Coordinator message substitution* (12-of-16, `--fault tbs-replace`): every participating
  signer independently detected that the commitment it received did not verify against the
  substituted message and refused to sign.
- *Corrupted shares* (15-of-16, `--fault bad-share`): with one corrupt signer, the coordinator
  identified and blacklisted the culprit and completed signing with the remaining 15. With two
  corrupt signers, it correctly failed — loudly, not silently — once only 14 remained against a
  threshold of 15.
- *Silent and non-responsive signers* (14-of-24, 5 silent + 5 never-committing + 14 honest):
  ROAST formed a first session, blacklisted the 5 signers that committed and then went silent,
  and completed on the second session — well inside the `n − t + 1 = 11` bound.

**Bandwidth** — fitted against `n` participants and `t` threshold:

| Mode | Bytes sent | R² |
| --- | --- | --- |
| DKG | `≈ 452 · n^2.154 · t^0.212` | 0.9982 |
| Signing | `≈ 771 · n^0.998 · t^0.696` | 0.9880 |
| Refresh | `≈ 434 · n^2.154 · t^0.218` | 0.9982 |

Extrapolated, a 100-of-100 committee needs roughly 25 MB for a DKG or refresh ceremony and
about 1.9 MB per signature — five to six orders of magnitude below the two-party garbled-circuit
baseline, though the two use entirely different mechanisms and aren't a strict comparison.
Up to a *t*-of-32 committee, sub-2 MB ceremonies and sub-0.5 MB signatures make hourly refresh
and thousands of certificates per day comfortably feasible.

## Repository layout

| Path | Role |
| --- | --- |
| `frost_signer_core/` | Rust crate wrapping `frost-ed25519`: DKG, refresh, commitments, signature shares, OpenSSH pubkey conversion |
| `frost_coordinator.c` | Coordinator: session orchestration, ROAST candidate-session management, share aggregation, certificate minting |
| `frost_signer.c` | Signer: participates in DKG, signing, and refresh; holds the mTLS identity and OAEP keypairs |
| `frost_common.h` | Shared message formats and protocol constants |
| `frost_stubs.c` | C ↔ Rust boundary; invokes the Rust binary as a subprocess and parses its output |
| `checkpoint.c` / `.h` | Wall-clock timing and logging instrumentation |
| `analyze_checkpoint_log.py` | Post-processing for checkpoint timing logs |
| `certs/` | mTLS and OAEP keypairs |
| `Makefile` | Builds the Rust core via Cargo, then the C coordinator and signer |

## Limitations

Stated plainly, because the design-level goals are largely met and the remaining distance to
production is implementation maturity:

- **Shares are unprotected at rest.** Signer secret shares live in ordinary process memory on
  commodity hardware. No memory locking, no zeroization on exit, no enclave or HSM backing.
- **No coordinator redundancy.** ROAST tolerates signer faults, not a coordinator crash.
  Because the coordinator is oblivious to all secrets, a replacement can in principle be spawned
  and signers re-pointed at it, but this isn't implemented or tested.
- **Inefficient transport encoding.** Data crosses the mTLS channel as hex text rather than raw
  bytes, and signer public keys contain long compressible runs of zero bytes. This inflates the
  bandwidth figures above; it is not a correctness or security issue.
- **Dated mTLS ciphersuite.** RSA-2048 identity keypairs rather than a modern ECDHE suite.
- **Unprofiled instrumentation overhead.** The `checkpoint` timing cost has not been separated
  out of the reported totals.
- **LAN only.** Tested to 32-of-32 over loopback and a single local Wi-Fi link. WAN behavior is
  untested.
- **Fixed committee.** Share refresh works within a fixed `(t, n)`; committee membership and
  threshold resizing (as in Dynamic-FROST) are not supported.
- **No policy layer.** Signers verify that a commitment matches the message, but do not evaluate
  whether the certificate itself is legitimate — blacklisted principals, excessive validity
  windows. Certificate-request legitimacy is a coordinator-side policy concern here.
- **Unaudited.** The composition of FROST + ROAST + mTLS + identity binding + refresh has not
  had external security review.

## Background reading

- Komlo & Goldberg, [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852)
- Connolly, Komlo, Goldberg & Wood, [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591) — the FROST protocol
- Bellare, Crites, Komlo, Maller, Tessaro & Zhu, [Better than Advertised Security for Non-Interactive Threshold Signatures](https://eprint.iacr.org/2022/833) — the TS-UF hierarchy
- Ruffing, Ronge, Jin, Schneider-Bensch & Schröder, [ROAST: Robust Asynchronous Schnorr Threshold Signatures](https://eprint.iacr.org/2022/550)
- Herzberg, Jarecki, Krawczyk & Yung, *Proactive Secret Sharing Or: How to Cope With Perpetual Leakage*, CRYPTO '95
- Harchol, Abraham & Pinkas, [Distributed SSH Key Management with Proactive RSA Threshold Signatures](https://eprint.iacr.org/2018/389) (ESKM)
- Zhou, Schneider & van Renesse, [COCA: A Secure Distributed Online Certification Authority](https://dl.acm.org/doi/10.1145/571637.571638)
- Jayaraman, Li & Evans, [Decentralized Certificate Authorities](https://arxiv.org/abs/1706.03370)

## License

MIT
