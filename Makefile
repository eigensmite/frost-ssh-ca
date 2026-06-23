#
# Makefile for FROST DKG coordinator/signer transport layer
# Mirrors the style of the base project Makefile.
#
CC          = gcc
EXECUTABLES = frost_coordinator frost_signer
INCLUDES    = $(wildcard *.h)
SOURCES     = $(wildcard *.c)
DEPS        = $(INCLUDES)
OBJECTS     = $(SOURCES:.c=.o)
OBJECTS    += $(SOURCES:.c=.dSYM*)
EXTRAS      = $(SOURCES:.c=.exe*)

CFLAGS  = -g -ggdb3 -std=c99 \
          -Wuninitialized -Wunused -Wunused-macros -Wunused-variable \
          -Wunused-function \
          -Wignored-qualifiers -Wshift-negative-value \
          -Wmain -Wreturn-type \
          -Winit-self -Wimplicit-int -Wimplicit-fallthrough \
          -Wparentheses -Wdangling-else \
          -Wreturn-type -Wredundant-decls -Wswitch-default -Wshadow \
          -Wformat=2 -Wformat-nonliteral -Wformat-y2k -Wformat-security \
          -Wextra -Wpedantic

LIBS    = -lgnutls

LDFLAGS =

all: $(EXECUTABLES)

frost_coordinator: frost_coordinator.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< $(LIBS)

frost_signer: frost_signer.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< $(LIBS)

# Generate self-signed test certificates (reuses the rootCA from base project)
# Run this once before testing if you don't already have certs/
certs:
	mkdir -p certs
	openssl genrsa -out certs/rootCA.key 4096
	openssl req -x509 -new -nodes -key certs/rootCA.key \
	    -sha256 -days 1024 -out certs/rootCA.crt \
	    -subj "/C=US/CN=FROST Test CA"
	# coordinator cert
	openssl genrsa -out certs/directorykey.pem 2048
	openssl req -new -key certs/directorykey.pem \
	    -out certs/directory.csr \
	    -subj "/C=US/CN=Directory Server"
	openssl x509 -req -in certs/directory.csr \
	    -CA certs/rootCA.crt -CAkey certs/rootCA.key \
	    -CAcreateserial -out certs/directory.crt -days 500 -sha256
	# signer 1 cert
	openssl genrsa -out certs/beocatkey.pem 2048
	openssl req -new -key certs/beocatkey.pem \
	    -out certs/beocat.csr \
	    -subj "/C=US/CN=BeoCat"
	openssl x509 -req -in certs/beocat.csr \
	    -CA certs/rootCA.crt -CAkey certs/rootCA.key \
	    -CAcreateserial -out certs/beocat.crt -days 500 -sha256
	# signer 2 cert
	openssl genrsa -out certs/footballkey.pem 2048
	openssl req -new -key certs/footballkey.pem \
	    -out certs/football.csr \
	    -subj "/C=US/CN=KSU Football"
	openssl x509 -req -in certs/football.csr \
	    -CA certs/rootCA.crt -CAkey certs/rootCA.key \
	    -CAcreateserial -out certs/football.crt -days 500 -sha256

.PHONY: clean certs
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES) $(EXTRAS)
