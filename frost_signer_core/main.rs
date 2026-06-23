//! frost_signer_core — called by the C signer via popen().
//!
//! Every subcommand reads blobs from stdin as hex lines and writes
//! blobs to stdout as hex lines.  Errors go to stderr.
//!
//! Wire convention (matches frost_signer.c stub comments):
//!
//!   dkg_part1  --id <u16> --n <u16> --t <u16>
//!     stdin:  (nothing)
//!     stdout: line 1 — hex(SecretPackage postcard bytes)   ← keep locally
//!             line 2 — hex(round1::Package postcard bytes) ← broadcast
//!
//!   dkg_part2  --id <u16> --n <u16> --t <u16>
//!     stdin:  line 1     — hex(round1::SecretPackage)
//!             line 2     — "<sender_id> <hex(round1::Package)>"  × (n-1)
//!     stdout: line 1     — hex(round2::SecretPackage)
//!             lines 2..n — "<target_id> <hex(round2::Package)>"  × (n-1)
//!
//!   dkg_part3  --id <u16> --n <u16> --t <u16>
//!     stdin:  line 1       — hex(round2::SecretPackage)
//!             lines 2..n   — "<sender_id> <hex(round1::Package)>"  × (n-1)
//!             lines n+1..  — "<sender_id> <hex(round2::Package)>"  × (n-1)
//!     stdout: line 1       — hex(KeyPackage postcard bytes)
//!             line 2       — hex(PublicKeyPackage postcard bytes)
//!
//!   commit  --id <u16>
//!     stdin:  line 1 — hex(KeyPackage)
//!     stdout: line 1 — hex(SigningNonces)   ← keep locally, never send
//!             line 2 — hex(SigningCommitments) ← send to coordinator
//!
//!   sign  --id <u16>
//!     stdin:  line 1 — hex(SigningNonces)
//!             line 2 — hex(KeyPackage)
//!             line 3 — hex(SigningPackage)  (assembled by coordinator)
//!     stdout: line 1 — hex(SignatureShare)

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::process;

use frost_ed25519 as frost;
use frost_ed25519::keys::dkg;

// ── Hex helpers ──────────────────────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {}", s.len()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| format!("bad hex byte at {}: {}", i, e))
        })
        .collect()
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i+1 < input.len() { input[i+1] as usize } else { 0 };
        let b2 = if i+2 < input.len() { input[i+2] as usize } else { 0 };
        out.push(CHARS[(b0 >> 2)] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        out.push(if i+1 < input.len() { CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char } else { '=' });
        out.push(if i+2 < input.len() { CHARS[b2 & 0x3f] as char } else { '=' });
        i += 3;
    }
    out
}

// ── stdin reader ─────────────────────────────────────────────────

fn read_line(stdin: &mut impl BufRead) -> Result<String, String> {
    let mut line = String::new();
    stdin
        .read_line(&mut line)
        .map_err(|e| format!("stdin read error: {}", e))?;
    Ok(line.trim().to_string())
}

fn read_hex_blob(stdin: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let line = read_line(stdin)?;
    if line.is_empty() {
        return Err("unexpected EOF on stdin".into());
    }
    from_hex(&line)
}

// ── Identifier helper ─────────────────────────────────────────────

fn identifier(id: u16) -> Result<frost::Identifier, String> {
    frost::Identifier::try_from(id).map_err(|e| format!("bad identifier {}: {:?}", id, e))
}


// -- 
use signature::Signer;
use ssh_key::{SigningKey, public::KeyData, Signature as SshSignature, Algorithm};

/* ── Pass 1: capture TBS ─────────────────────────────────────── */
struct TbsCapture {
    pub_key: KeyData,
    tbs: std::cell::RefCell<Vec<u8>>,
}

impl Signer<SshSignature> for TbsCapture {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<SshSignature, signature::Error> {
        *self.tbs.borrow_mut() = msg.to_vec();
        /* return a placeholder — the Certificate produced here is discarded */
        Ok(SshSignature::new(Algorithm::Ed25519, vec![0u8; 64])
            .map_err(|_| signature::Error::new())?)
    }
}

impl SigningKey for TbsCapture {
    fn public_key(&self) -> KeyData { self.pub_key.clone() }
}

/* ── Pass 2: inject real signature ──────────────────────────── */
struct FrostInject {
    pub_key: KeyData,
    sig_bytes: Vec<u8>,
}

impl Signer<SshSignature> for FrostInject {
    fn try_sign(&self, _msg: &[u8]) -> std::result::Result<SshSignature, signature::Error> {
        SshSignature::new(Algorithm::Ed25519, self.sig_bytes.clone())
            .map_err(|_| signature::Error::new())
    }
}

impl SigningKey for FrostInject {
    fn public_key(&self) -> KeyData { self.pub_key.clone() }
}

// ── Subcommand implementations ────────────────────────────────────

/// dkg_part1 --id <u16> --n <u16> --t <u16>
fn cmd_dkg_part1(id: u16, n: u16, t: u16) -> Result<(), String> {
    let mut rng = rand::thread_rng();
    let ident = identifier(id)?;

    let (secret_pkg, pub_pkg) = dkg::part1(ident, n, t, &mut rng)
        .map_err(|e| format!("dkg::part1 failed: {:?}", e))?;

    // SecretPackage — keep locally (never sent over the wire)
    let secret_bytes = secret_pkg
        .serialize()
        .map_err(|e| format!("SecretPackage serialize: {:?}", e))?;

    // round1::Package — broadcast to all peers via coordinator
    let pkg_bytes = pub_pkg
        .serialize()
        .map_err(|e| format!("round1::Package serialize: {:?}", e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", to_hex(&secret_bytes)).map_err(|e| e.to_string())?;
    writeln!(out, "{}", to_hex(&pkg_bytes)).map_err(|e| e.to_string())?;
    Ok(())
}

/// dkg_part2 --id <u16> --n <u16> --t <u16>
///
/// stdin layout:
///   line 1:   hex(round1::SecretPackage)
///   lines 2..(n): "<sender_id_decimal> <hex(round1::Package)>"
fn cmd_dkg_part2(id: u16, n: u16) -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();

    // Read our own round-1 secret package
    let secret_bytes = read_hex_blob(&mut input)?;
    let secret_pkg =
        dkg::round1::SecretPackage::deserialize(&secret_bytes)
            .map_err(|e| format!("round1::SecretPackage deserialize: {:?}", e))?;

    // Read n-1 peer round-1 packages
    let mut round1_pkgs: BTreeMap<frost::Identifier, dkg::round1::Package> = BTreeMap::new();
    for _ in 0..(n - 1) {
        let line = read_line(&mut input)?;
        if line.is_empty() {
            return Err("unexpected EOF reading peer r1 packages".into());
        }
        let mut parts = line.splitn(2, ' ');
        let sender_id: u16 = parts
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|e| format!("bad sender_id: {}", e))?;
        let pkg_hex = parts.next().ok_or("missing r1 pkg hex")?;
        let pkg_bytes = from_hex(pkg_hex)?;
        let pkg = dkg::round1::Package::deserialize(&pkg_bytes)
            .map_err(|e| format!("round1::Package deserialize from peer {}: {:?}", sender_id, e))?;
        round1_pkgs.insert(identifier(sender_id)?, pkg);
    }

    let (secret2_pkg, round2_pkgs) = dkg::part2(secret_pkg, &round1_pkgs)
        .map_err(|e| format!("dkg::part2 failed: {:?}", e))?;

    // Output: round2 SecretPackage first, then one line per target
    let secret2_bytes = secret2_pkg
        .serialize()
        .map_err(|e| format!("round2::SecretPackage serialize: {:?}", e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", to_hex(&secret2_bytes)).map_err(|e| e.to_string())?;

    // round2_pkgs: BTreeMap<Identifier, round2::Package>
    // Each entry is a unicast package for the peer with that identifier.
    // We need to emit the target ID as a decimal prefix so the C side
    // knows where to route it.
    for (target_ident, pkg) in &round2_pkgs {
        let pkg_bytes = pkg
            .serialize()
            .map_err(|e| format!("round2::Package serialize: {:?}", e))?;
        // Identifier → u16: serialize gives us the scalar bytes; we parse
        // the little-endian u16 from the first two bytes (identifiers are
        // always small integers in practice).
        let id_bytes = target_ident.serialize();
        let target_id = u16::from_le_bytes([id_bytes[0], id_bytes[1]]);
        writeln!(out, "{} {}", target_id, to_hex(&pkg_bytes)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// dkg_part3 --id <u16> --n <u16> --t <u16>
///
/// stdin layout:
///   line 1:        hex(round2::SecretPackage)
///   lines 2..n:    "<sender_id> <hex(round1::Package)>"   — peer r1 packages
///   lines n+1..2n: "<sender_id> <hex(round2::Package)>"   — peer r2 packages
fn cmd_dkg_part3(n: u16) -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();

    // round2 secret package
    let secret2_bytes = read_hex_blob(&mut input)?;
    let secret2_pkg =
        dkg::round2::SecretPackage::deserialize(&secret2_bytes)
            .map_err(|e| format!("round2::SecretPackage deserialize: {:?}", e))?;

    // n-1 round-1 packages from peers (same format as part2 input)
    let mut round1_pkgs: BTreeMap<frost::Identifier, dkg::round1::Package> = BTreeMap::new();
    for _ in 0..(n - 1) {
        let line = read_line(&mut input)?;
        if line.is_empty() {
            return Err("unexpected EOF reading peer r1 packages in part3".into());
        }
        let mut parts = line.splitn(2, ' ');
        let sender_id: u16 = parts
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|e| format!("bad sender_id: {}", e))?;
        let pkg_hex = parts.next().ok_or("missing r1 pkg hex in part3")?;
        let pkg_bytes = from_hex(pkg_hex)?;
        let pkg = dkg::round1::Package::deserialize(&pkg_bytes)
            .map_err(|e| format!("round1::Package deserialize in part3: {:?}", e))?;
        round1_pkgs.insert(identifier(sender_id)?, pkg);
    }

    // n-1 round-2 packages addressed to us, one from each peer
    let mut round2_pkgs: BTreeMap<frost::Identifier, dkg::round2::Package> = BTreeMap::new();
    for _ in 0..(n - 1) {
        let line = read_line(&mut input)?;
        if line.is_empty() {
            return Err("unexpected EOF reading peer r2 packages".into());
        }
        let mut parts = line.splitn(2, ' ');
        let sender_id: u16 = parts
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|e| format!("bad sender_id in r2: {}", e))?;
        let pkg_hex = parts.next().ok_or("missing r2 pkg hex")?;
        let pkg_bytes = from_hex(pkg_hex)?;
        let pkg = dkg::round2::Package::deserialize(&pkg_bytes)
            .map_err(|e| format!("round2::Package deserialize: {:?}", e))?;
        round2_pkgs.insert(identifier(sender_id)?, pkg);
    }

    let (key_pkg, pub_key_pkg) = dkg::part3(&secret2_pkg, &round1_pkgs, &round2_pkgs)
        .map_err(|e| format!("dkg::part3 failed: {:?}", e))?;

    let key_bytes = key_pkg
        .serialize()
        .map_err(|e| format!("KeyPackage serialize: {:?}", e))?;
    let pub_bytes = pub_key_pkg
        .serialize()
        .map_err(|e| format!("PublicKeyPackage serialize: {:?}", e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", to_hex(&key_bytes)).map_err(|e| e.to_string())?;
    writeln!(out, "{}", to_hex(&pub_bytes)).map_err(|e| e.to_string())?;
    Ok(())
}

/// commit --id <u16>
///
/// stdin:  line 1 — hex(KeyPackage)
/// stdout: line 1 — hex(SigningNonces)       ← keep locally
///         line 2 — hex(SigningCommitments)  ← send to coordinator
fn cmd_commit() -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut rng = rand::thread_rng();

    let key_bytes = read_hex_blob(&mut input)?;
    let key_pkg = frost::keys::KeyPackage::deserialize(&key_bytes)
        .map_err(|e| format!("KeyPackage deserialize: {:?}", e))?;

    let (nonces, commitments) =
        frost::round1::commit(key_pkg.signing_share(), &mut rng);

    let nonces_bytes = nonces
        .serialize()
        .map_err(|e| format!("SigningNonces serialize: {:?}", e))?;
    let commit_bytes = commitments
        .serialize()
        .map_err(|e| format!("SigningCommitments serialize: {:?}", e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", to_hex(&nonces_bytes)).map_err(|e| e.to_string())?;
    writeln!(out, "{}", to_hex(&commit_bytes)).map_err(|e| e.to_string())?;
    Ok(())
}

/// sign --id <u16>
///
/// stdin:  line 1 — hex(SigningNonces)
///         line 2 — hex(KeyPackage)
///         line 3 — hex(SigningPackage)   assembled by the coordinator
/// stdout: line 1 — hex(SignatureShare)
fn cmd_sign() -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();

    let nonces_bytes  = read_hex_blob(&mut input)?;
    let key_bytes     = read_hex_blob(&mut input)?;
    let signing_bytes = read_hex_blob(&mut input)?;

    let nonces = frost::round1::SigningNonces::deserialize(&nonces_bytes)
        .map_err(|e| format!("SigningNonces deserialize: {:?}", e))?;
    let key_pkg = frost::keys::KeyPackage::deserialize(&key_bytes)
        .map_err(|e| format!("KeyPackage deserialize: {:?}", e))?;
    let signing_pkg = frost::SigningPackage::deserialize(&signing_bytes)
        .map_err(|e| format!("SigningPackage deserialize: {:?}", e))?;

    let sig_share = frost::round2::sign(&signing_pkg, &nonces, &key_pkg)
        .map_err(|e| format!("frost::round2::sign failed: {:?}", e))?;

    let share_bytes = sig_share.serialize();

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", to_hex(&share_bytes)).map_err(|e| e.to_string())?;
    Ok(())
}

/// aggregate
///
/// Coordinator-side aggregation.  The coordinator can call this after
/// collecting t signature shares.
///
/// stdin:  line 1      — hex(SigningPackage)
///         line 2      — hex(PublicKeyPackage)
///         lines 3..t+2 — "<signer_id> <hex(SignatureShare)>"
/// stdout: line 1      — hex(final Signature, 64 bytes for Ed25519)
fn cmd_aggregate(t: u16) -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();

    let signing_bytes = read_hex_blob(&mut input)?;
    let pub_key_bytes = read_hex_blob(&mut input)?;

    let signing_pkg = frost::SigningPackage::deserialize(&signing_bytes)
        .map_err(|e| format!("SigningPackage deserialize: {:?}", e))?;
    let pub_key_pkg = frost::keys::PublicKeyPackage::deserialize(&pub_key_bytes)
        .map_err(|e| format!("PublicKeyPackage deserialize: {:?}", e))?;

    let mut shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> = BTreeMap::new();
    for _ in 0..t {
        let line = read_line(&mut input)?;
        if line.is_empty() {
            return Err("unexpected EOF reading signature shares".into());
        }
        let mut parts = line.splitn(2, ' ');
        let signer_id: u16 = parts
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|e| format!("bad signer_id in share: {}", e))?;
        let share_hex = parts.next().ok_or("missing share hex")?;
        let share_bytes = from_hex(share_hex)?;
        let share = frost::round2::SignatureShare::deserialize(&share_bytes)
            .map_err(|e| format!("SignatureShare deserialize: {:?}", e))?;
        shares.insert(identifier(signer_id)?, share);
    }

    let signature = frost::aggregate(&signing_pkg, &shares, &pub_key_pkg)
        .map_err(|e| format!("frost::aggregate failed: {:?}", e))?;

    let sig_bytes = signature
        .serialize()
        .map_err(|e| format!("Signature serialize: {:?}", e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", to_hex(&sig_bytes)).map_err(|e| e.to_string())?;
    Ok(())
}

/// pubkey
///
/// stdin:  line 1 — hex(PublicKeyPackage postcard bytes)
/// stdout: line 1 — "ssh-ed25519 <base64> frost-ca"
fn cmd_pubkey() -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();

    let pkg_bytes = read_hex_blob(&mut input)?;
    let pub_key_pkg = frost::keys::PublicKeyPackage::deserialize(&pkg_bytes)
        .map_err(|e| format!("PublicKeyPackage deserialize: {:?}", e))?;

    // Raw 32-byte compressed Edwards point
    let vk_bytes = pub_key_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| format!("VerifyingKey serialize: {:?}", e))?;

    // OpenSSH wire format for ed25519 public key:
    //   string  "ssh-ed25519"       (4-byte length prefix + bytes)
    //   string  key_bytes           (4-byte length prefix + 32 bytes)
    // Then the whole thing is base64-encoded.
    let algo = b"ssh-ed25519";
    let mut wire = Vec::new();

    // length-prefixed algorithm name
    wire.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    wire.extend_from_slice(algo);

    // length-prefixed key bytes
    wire.extend_from_slice(&(vk_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&vk_bytes);

    // base64 encode — use the standard alphabet
    let b64 = base64_encode(&wire);

    println!("ssh-ed25519 {} frost-ca", b64);
    Ok(())
}

/// assemble
///
/// Builds a FROST SigningPackage from raw ingredients and returns
/// the postcard-serialized bytes for signers to use with `sign`.
///
/// stdin:  line 1      — hex(raw TBS message bytes)
///         line 2      — number of commitments t
///         lines 3..t+2 — "<signer_id> <hex(SigningCommitments)>"
/// stdout: line 1      — hex(SigningPackage postcard bytes)
fn cmd_assemble() -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();

    let msg_bytes = read_hex_blob(&mut input)?;

    let t_line = read_line(&mut input)?;
    let t: u16 = t_line.trim().parse()
        .map_err(|e| format!("bad t: {}", e))?;

    let mut commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        BTreeMap::new();

    for _ in 0..t {
        let line = read_line(&mut input)?;
        let mut parts = line.splitn(2, ' ');
        let signer_id: u16 = parts.next().unwrap_or("").parse()
            .map_err(|e| format!("bad signer_id: {}", e))?;
        let commit_hex = parts.next().ok_or("missing commitment hex")?;
        let commit_bytes = from_hex(commit_hex)?;
        let commit = frost::round1::SigningCommitments::deserialize(&commit_bytes)
            .map_err(|e| format!("SigningCommitments deserialize: {:?}", e))?;
        commitments.insert(identifier(signer_id)?, commit);
    }

    let signing_pkg = frost::SigningPackage::new(commitments, &msg_bytes);
    let pkg_bytes = signing_pkg.serialize()
        .map_err(|e| format!("SigningPackage serialize: {:?}", e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", to_hex(&pkg_bytes)).map_err(|e| e.to_string())?;
    Ok(())
}

/// verify
///
/// stdin:  line 1 — hex(message bytes)
///         line 2 — hex(Signature, 64 bytes)
///         line 3 — hex(PublicKeyPackage)
/// stdout: "OK" or error
fn cmd_verify() -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();

    let msg_bytes  = read_hex_blob(&mut input)?;
    let sig_bytes  = read_hex_blob(&mut input)?;
    let pkg_bytes  = read_hex_blob(&mut input)?;

    let sig = frost::Signature::deserialize(&sig_bytes)
        .map_err(|e| format!("Signature deserialize: {:?}", e))?;
    let pub_key_pkg = frost::keys::PublicKeyPackage::deserialize(&pkg_bytes)
        .map_err(|e| format!("PublicKeyPackage deserialize: {:?}", e))?;

    pub_key_pkg.verifying_key()
        .verify(&msg_bytes, &sig)
        .map_err(|e| format!("INVALID: {:?}", e))?;

    println!("OK");
    Ok(())
}

/// tbs — extract TBS bytes from a certificate to-be-signed
///
/// stdin:  line 1 — path to user public key file
///         line 2 — serial (u64)
///         line 3 — principal (username)
///         line 4 — valid_after  (unix seconds)
///         line 5 — valid_before (unix seconds)
/// stdout: line 1 — hex(TBS bytes)  ← feed to SIGN
///         line 2 — hex(builder state encoded as cert with dummy sig)
///                  ← save this, pass to mint
fn cmd_tbs() -> Result<(), String> {
    use ssh_key::{certificate::{self, CertType}, PublicKey};

    let stdin = io::stdin();
    let mut input = stdin.lock();

    let pubkey_path   = read_line(&mut input)?;
    let serial: u64   = read_line(&mut input)?.trim().parse()
        .map_err(|e| format!("bad serial: {}", e))?;
    let principal     = read_line(&mut input)?;
    let valid_after: u64  = read_line(&mut input)?.trim().parse()
        .map_err(|e| format!("bad valid_after: {}", e))?;
    let valid_before: u64 = read_line(&mut input)?.trim().parse()
        .map_err(|e| format!("bad valid_before: {}", e))?;

    let pubkey = PublicKey::read_openssh_file(pubkey_path.trim().as_ref())
        .map_err(|e| format!("read pubkey: {}", e))?;

    let nonce: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

    let mut builder = certificate::Builder::new(
            nonce,
            pubkey.key_data().clone(),
            valid_after,
            valid_before,
        )
        .map_err(|e| format!("builder: {}", e))?;

    builder.serial(serial).map_err(|e| format!("serial: {}", e))?;
    builder.key_id("frost-ca").map_err(|e| format!("key_id: {}", e))?;
    builder.cert_type(CertType::User).map_err(|e| format!("cert_type: {}", e))?;
    builder.valid_principal(principal.trim()).map_err(|e| format!("principal: {}", e))?;

    let capture = TbsCapture {
        pub_key: pubkey.key_data().clone(),
        tbs: std::cell::RefCell::new(Vec::new()),
    };

    /* sign() calls try_sign() which captures TBS into capture.tbs */
    let dummy_cert = builder.sign(&capture)
        .map_err(|e| format!("tbs capture: {}", e))?;

    let tbs = capture.tbs.borrow();

    /* line 1: TBS hex — feed to coordinator SIGN command */
    println!("{}", to_hex(&tbs));

    /* line 2: dummy cert OpenSSH string — save as template for mint */
    println!("{}", dummy_cert.to_openssh()
        .map_err(|e| format!("cert encode: {}", e))?);

    Ok(())
}

/// mint — replace dummy signature with real FROST signature
///
/// stdin:  line 1 — OpenSSH cert string from tbs (with dummy sig)
///         line 2 — hex(64-byte FROST signature from aggregate)
///         line 3 — hex(TBS bytes, same as fed to SIGN — for verification)
/// stdout: OpenSSH certificate with real signature
fn cmd_mint() -> Result<(), String> {
    use ssh_key::Certificate;

    let stdin = io::stdin();
    let mut input = stdin.lock();

    let cert_str  = read_line(&mut input)?;
    let sig_hex   = read_line(&mut input)?;
    let tbs_hex   = read_line(&mut input)?;

    let sig_bytes = from_hex(sig_hex.trim())?;
    let tbs_bytes = from_hex(tbs_hex.trim())?;

    /* parse the dummy cert to extract all fields */
    let dummy_cert: Certificate = cert_str.trim().parse()
        .map_err(|e| format!("parse cert: {}", e))?;

    /* rebuild with real signature using the same fields */
    let nonce     = dummy_cert.nonce().to_vec();
    let pub_key   = dummy_cert.public_key().clone();
    let valid_after  = dummy_cert.valid_after();
    let valid_before = dummy_cert.valid_before();

    let mut builder = ssh_key::certificate::Builder::new(
            nonce,
            pub_key.clone(),
            valid_after,
            valid_before,
        )
        .map_err(|e| format!("builder: {}", e))?;

    builder.serial(dummy_cert.serial()).map_err(|e| format!("serial: {}", e))?;
    builder.key_id(dummy_cert.key_id()).map_err(|e| format!("key_id: {}", e))?;
    builder.cert_type(dummy_cert.cert_type()).map_err(|e| format!("cert_type: {}", e))?;
    for p in dummy_cert.valid_principals() {
        builder.valid_principal(p).map_err(|e| format!("principal: {}", e))?;
    }
let comment = dummy_cert.comment();
if !comment.is_empty() {
    builder.comment(comment).map_err(|e| format!("comment: {}", e))?;
}
    let inject = FrostInject { pub_key, sig_bytes };
    let cert = builder.sign(&inject)
        .map_err(|e| format!("sign inject: {}", e))?;

    println!("{}", cert.to_openssh()
        .map_err(|e| format!("cert encode: {}", e))?);
    Ok(())
}

// ── Argument parsing ──────────────────────────────────────────────

fn get_flag(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn require_u16(args: &[String], flag: &str) -> Result<u16, String> {
    get_flag(args, flag)
        .ok_or_else(|| format!("missing flag {}", flag))?
        .parse::<u16>()
        .map_err(|e| format!("invalid {}: {}", flag, e))
}

// ── Entry point ───────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: frost_signer_core <subcommand> [--id N] [--n N] [--t N]");
        eprintln!("Subcommands: dkg_part1  dkg_part2  dkg_part3  commit  sign  aggregate");
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "dkg_part1" => {
            let id = require_u16(&args, "--id");
            let n  = require_u16(&args, "--n");
            let t  = require_u16(&args, "--t");
            match (id, n, t) {
                (Ok(id), Ok(n), Ok(t)) => cmd_dkg_part1(id, n, t),
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
            }
        }
        "dkg_part2" => {
            let id = require_u16(&args, "--id");
            let n  = require_u16(&args, "--n");
            match (id, n) {
                (Ok(_id), Ok(n)) => cmd_dkg_part2(_id, n),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
        "dkg_part3" => {
            let n = require_u16(&args, "--n");
            match n {
                Ok(n) => cmd_dkg_part3(n),
                Err(e) => Err(e),
            }
        }
        "commit" => cmd_commit(),
        "sign"   => cmd_sign(),
        "aggregate" => {
            let t = require_u16(&args, "--t");
            match t {
                Ok(t) => cmd_aggregate(t),
                Err(e) => Err(e),
            }
        }
        "pubkey" => cmd_pubkey(),
        "assemble" => cmd_assemble(),
        "verify" => cmd_verify(),
        "tbs" => cmd_tbs(),
        "mint" => cmd_mint(),
        other => Err(format!("unknown subcommand: {}", other)),
    };

    if let Err(e) = result {
        eprintln!("ERROR: {}", e);
        process::exit(1);
    }
}
