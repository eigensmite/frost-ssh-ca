# frost-ssh-ca

Repository: https://github.com/eigensmite/frost-ssh-ca

## Build

1. Build the Rust FROST core:

   ```bash
   cd frost_signer_core && cargo build
   ```

2. Build the coordinator and signer binaries:

   ```bash
   make
   ```

3. (Optional) Regenerate certs/keypairs if required:

   ```bash
   ./gen_tls_certs.sh
   ```

## Running

### Start the coordinator

Start a single coordinator process:

```bash
./frost_coordinator <dkg/sign/refresh> [--t <t>] [--n <n>] [--principal <name>]
```

### Start the signers

Start up to `n` signer processes, each as:

```bash
./frost_signer <id> <t> <n>
```

To automate launching all signers at once:

```bash
N=<n>; T=<t>
for i in $(seq 1 $N); do
  ./frost_signer $i $N $T &
done
```

## Usage Notes

- Perform a **DKG** operation first to generate the key share material.
- To perform a **signing** operation:
  - You must specify a `user_key.pub`, or have one present in the directory under that name.
  - You must specify the `--principal`.

## Extracting the SSH-Compatible Pubkey

Extract an SSH-compatible Ed25519 public key with:

```bash
cat ./pub_key_pkg.hex | /frost_signer_core/target/debug/frost_signer_core pubkey > ca.pub
```
