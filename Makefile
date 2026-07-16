# Makefile — FROST distributed SSH CA
#
# Targets:
#   all          build coordinator and both signers
#   dkg          run a 2-of-2 DKG session (generates key shares)
#   sign         run a signing session (issues user_key-cert.pub)
#   verify       inspect the issued certificate with ssh-keygen -L
#   clean        remove binaries and generated artefacts
#   clean-shares remove persisted key shares (forces new DKG)
#   help         print usage summary

CC      = gcc
CFLAGS  = -g -std=c99 -Wall -Wextra -Wpedantic \
           -Wno-unused-function -Wno-unused-variable \
           -Wno-missing-field-initializers
LDFLAGS = -lgnutls

# Path to the compiled Rust FROST core binary.
# Override:  make all FROST_CORE=./target/release/frost_signer_core
FROST_CORE ?= ./frost_signer_core/target/debug/frost_signer_core

FROST_DEF = -DFROST_CORE_BIN=\"$(FROST_CORE)\"

# Default parameters (override on command line)
N        ?= 2
T        ?= 2
USER_KEY ?= user_key.pub
PRINCIPAL?= user
SERIAL   ?= 1
VALIDITY ?= 86400
OUTPUT   ?= user_key-cert.pub

.PHONY: all dkg dkg-coord dkg-signer1 dkg-signer2 \
        sign sign-coord sign-signer1 sign-signer2 \
        verify clean clean-shares help

all: frost_coordinator frost_signer

# ── Binaries ─────────────────────────────────────────────────────

frost_coordinator: frost_coordinator.c frost_common.h frost_stubs.c
	$(CC) $(CFLAGS) $(FROST_DEF) -o $@ frost_coordinator.c $(LDFLAGS)

frost_signer: frost_signer.c frost_common.h frost_stubs.c
	$(CC) $(CFLAGS) $(FROST_DEF) -o $@ frost_signer.c $(LDFLAGS)

# ── DKG mode ─────────────────────────────────────────────────────
# Run each in a separate terminal, coordinator first.

dkg-coord:
	mkdir -p shares
	./frost_coordinator dkg --n $(N) --t $(T)

dkg-signer: frost_signer
	./frost_signer certs/beocat.crt certs/beocatkey.pem $(N) $(T)

# Convenience: all three in background (requires job control)
dkg: all
	@echo "Starting DKG session (n=$(N), t=$(T))..."
	@mkdir -p shares
	@./frost_coordinator dkg --n $(N) --t $(T) &
	@sleep 0.4
	@./frost_signer certs/beocat.crt certs/beocatkey.pem $(N) $(T) &
	@wait
	@echo "DKG complete -- key shares in ./shares/"

# ── SIGN mode ────────────────────────────────────────────────────
# Run each in a separate terminal, coordinator first.

sign-coord:
	./frost_coordinator sign \
	    --user-key  $(USER_KEY) \
	    --principal $(PRINCIPAL) \
	    --n         $(N) \
	    --t         $(T) \
	    --serial    $(SERIAL) \
	    --validity  $(VALIDITY) \
	    --output    $(OUTPUT)

sign-signer: frost_signer
	./frost_signer certs/football.crt certs/footballkey.pem $(N) $(T)

# Convenience: all three in background
sign: all
	@echo "Starting signing session..."
	@echo "  user key:  $(USER_KEY)"
	@echo "  principal: $(PRINCIPAL)"
	@echo "  output:    $(OUTPUT)"
	@./frost_coordinator sign \
	    --user-key $(USER_KEY) --principal $(PRINCIPAL) \
	    --n $(N) --t $(T) --serial $(SERIAL) \
	    --validity $(VALIDITY) --output $(OUTPUT) &
	@sleep 0.4
	@./frost_signer certs/beocat.crt   certs/beocatkey.pem   $(N) $(T) &
	@wait
	@echo "Done -- certificate at $(OUTPUT)"

# ── Verification ─────────────────────────────────────────────────
verify:
	ssh-keygen -L -f $(OUTPUT)

# ── Cleanup ──────────────────────────────────────────────────────
clean:
	rm -f frost_coordinator frost_signer	
	rm -f pub_key_pkg.hex frost_ca_signer_*.pub signature_pkg.hex
	rm -f $(OUTPUT)

clean-shares:
	rm -rf shares/

help:
	@echo ""
	@echo "FROST distributed SSH CA -- build and run targets"
	@echo ""
	@echo "  make all                           build coordinator + signers"
	@echo "  make dkg  [N=n T=t]                run full DKG session"
	@echo "  make sign [USER_KEY=f PRINCIPAL=p] issue an SSH certificate"
	@echo "  make verify [OUTPUT=f]             inspect issued certificate"
	@echo "  make clean                         remove binaries + outputs"
	@echo "  make clean-shares                  remove persisted key shares"
	@echo ""
	@echo "Manual mode (separate terminals):"
	@echo "  Term 1:  make dkg-coord"
	@echo "  Term 2:  make dkg-signer1"
	@echo "  Term 3:  make dkg-signer2"
	@echo ""
	@echo "  Term 1:  make sign-coord USER_KEY=user_key.pub PRINCIPAL=alice"
	@echo "  Term 2:  make sign-signer1"
	@echo "  Term 3:  make sign-signer2"
	@echo ""
