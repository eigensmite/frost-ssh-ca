#!/bin/bash
# gen_tls_certs.sh - generate coordinator + 16 signer leaf certificates
# Requires: ./certs/rootCA.crt and certs/rootCAkey.pem already exist
set -e
cd "$(dirname "$0")"

NUM_SIGNERS=96

echo "Generating coordinator certificate..."
openssl genrsa -out certs/coordinatorkey.pem 2048

# SAN extension file for coordinator
cat > certs/coordinator_ext.cnf << 'EOF'
subjectAltName = DNS:localhost,DNS:coordinator,IP:127.0.0.1
EOF

openssl req -new -key certs/coordinatorkey.pem \
    -subj "/CN=coordinator" \
    -out certs/coordinator.csr

openssl x509 -req                      \
    -in      certs/coordinator.csr     \
    -CA      certs/rootCA.crt          \
    -CAkey   certs/rootCAkey.pem       \
    -CAcreateserial                    \
    -days    730                       \
    -extfile certs/coordinator_ext.cnf \
    -out     certs/coordinator.crt

rm certs/coordinator.csr certs/coordinator_ext.cnf
echo "  → certs/coordinator.crt"

for i in $(seq 1 $NUM_SIGNERS); do
    echo "Generating signer ${i} certificate..."
    openssl genrsa -out certs/signer${i}key.pem 2048

    # SAN extension file per signer
    cat > certs/signer${i}_ext.cnf << EOF
subjectAltName = DNS:signer${i},IP:127.0.0.1
EOF

    openssl req -new \
        -key  certs/signer${i}key.pem \
        -subj "/CN=signer${i}" \
        -out  certs/signer${i}.csr

    openssl x509 -req \
        -in      certs/signer${i}.csr \
        -CA      certs/rootCA.crt \
        -CAkey   certs/rootCAkey.pem \
        -CAcreateserial \
        -days    730 \
        -extfile certs/signer${i}_ext.cnf \
        -out     certs/signer${i}.crt

    rm certs/signer${i}.csr certs/signer${i}_ext.cnf
    echo "  → certs/signer${i}.crt"
done

for i in $(seq 1 $NUM_SIGNERS); do
    echo "Generating signer ${i} certificate..."
    openssl genrsa -out certs/signer${i}key_oaep.pem 2048
    # SAN extension file per signer
    cat > certs/signer${i}_oaep_ext.cnf << EOF
subjectAltName = DNS:signer${i},IP:127.0.0.1
EOF

    openssl req -new \
        -key  certs/signer${i}key_oaep.pem \
        -subj "/CN=signer${i}" \
        -out  certs/signer${i}_oaep.csr

    openssl x509 -req \
        -in      certs/signer${i}_oaep.csr \
        -CA      certs/rootCA.crt \
        -CAkey   certs/rootCAkey.pem \
        -CAcreateserial \
        -days    730 \
        -extfile certs/signer${i}_oaep_ext.cnf \
        -out     certs/signer${i}_oaep.crt

    rm certs/signer${i}_oaep.csr certs/signer${i}_oaep_ext.cnf
    echo "  → certs/signer${i}_oaep.crt"
done

echo ""
echo "Done. $(ls certs/*.crt | wc -l) certificates in certs/"
echo "Coordinator: certs/coordinator.crt"
echo "Signers:     certs/signer{1..16}.crt"
echo "Signers:     certs/signer{1..16}_oaep.crt"
