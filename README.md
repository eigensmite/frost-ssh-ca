# frost-ssh-ca
FROST DKG-based SSH CA master key virtualization 

build rust frost tool with `cargo` in frost_signer_core

make coordinator and signer with `make`

run single coordinator with `./frost_coordinator`

run up to `n` signers with `./frost_signer <cert.crt> <key.pem> <t> <n>`

after handshake / DKG complete, use `SIGN <m>` in `frost_coordinator` terminal to sign `m`.
