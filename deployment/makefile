RANDFILE                = ~/.rnd
ERROR_LOG		= /dev/null

# Directories
TLS_DIR	= ../TLS
CA_DIR	= ../CA
CRL_DIR = ../CA/crl
KEY_DIR	= $(CA_DIR)/private

# CA Variables
CA_KEY	= $(KEY_DIR)/ca-key.pem
CA_CERT	= $(CA_DIR)/ca-cert.pem
CONFIG	= $(CA_DIR)/imoviesca.cnf
SERIAL	= $(CA_DIR)/serial
INDEX	= $(CA_DIR)/index.txt
CRL	= $(CRL_DIR)/crl.pem
CRLNUM	= $(CRL_DIR)/crlnumber.txt

# TLS certificates and keys
WEB_CERT	= $(TLS_DIR)/web-cert.pem
WEB_KEY		= $(TLS_DIR)/web-key.pem
DB_CERT		= $(TLS_DIR)/db-cert.pem
DB_KEY		= $(TLS_DIR)/db-key.pem
BACKUP_CERT	= $(TLS_DIR)/backup-cert.pem
BACKUP_KEY	= $(TLS_DIR)/backup-key.pem
CA_TLS_CERT	= $(CA_DIR)/ca-tls-cert.pem
CA_TLS_KEY	= $(KEY_DIR)/ca-tls-key.pem
ARCHIVE_CERT	= $(CA_DIR)/archive-cert.pem
ARCHIVE_KEY	= $(KEY_DIR)/archive-key.pem

# Multitarget variables
TLS_KEYS = $(WEB_KEY) $(DB_KEY) $(BACKUP_KEY) $(CA_TLS_KEY) $(ARCHIVE_KEY)
CERTIFICATES = $(WEB_CERT) $(DB_CERT) $(BACKUP_CERT) $(CA_TLS_CERT) $(ARCHIVE_CERT)

# Deployment files
DEP_CNF = imoviesca.cnf

.PHONY: clean all

all: $(CERTIFICATES) $(CRL)

# Make Directories
$(TLS_DIR):
	mkdir $(TLS_DIR)
$(CA_DIR):
	mkdir $(CA_DIR)
$(KEY_DIR):
	mkdir -p $(KEY_DIR)
$(CRL_DIR):
	mkdir -p $(CRL_DIR)

# File setup
$(CONFIG): $(DEP_CNF) | $(CA_DIR)
	cp $(DEP_CNF) $(CONFIG)
$(SERIAL): | $(CA_DIR)
	echo "01" > $(SERIAL)
$(INDEX): | $(CA_DIR)
	touch $(INDEX)
	echo "unique_subject = no" > $(INDEX).attr
$(CRLNUM): | $(CRL_DIR)
	echo "01" > $(CRLNUM)
	
# Make CA certificate and private key
$(CA_KEY): | $(KEY_DIR) $(RANDFILE) $(ERROR_LOG)
	openssl genrsa -rand $(RANDFILE) -out $(CA_KEY) 4096 2> $(ERROR_LOG)
$(CA_CERT): $(CA_KEY) | $(CA_DIR) $(CONFIG) $(RANDFILE)
	openssl req -new -x509 -days 3650 -key $(CA_KEY) -out $(CA_CERT) -subj /O="iMovies"/OU="PKI Infrastructure"/commonName="iMovies Certificate Authority" -config $(CONFIG) -rand $(RANDFILE)

# Make the CRL files
$(CRL): $(CA_KEY) $(CA_CERT) | $(CRL_DIR) $(INDEX) $(CONFIG) $(CRLNUM)
	openssl ca -gencrl -config $(CONFIG) -out $(CRL)
	
# Make the TLS certificates and private keys
$(TLS_KEYS): | $(TLS_DIR) $(CA_DIR) $(KEY_DIR) $(RANDFILE) $(ERROR_LOG)
	openssl genrsa -rand $(RANDFILE) -out $@ 2048 2> $(ERROR_LOG)
$(WEB_CERT): $(WEB_KEY) $(CA_CERT) $(CA_KEY) | $(TLS_DIR) $(SERIAL) $(RANDFILE) $(CONFIG) $(ERROR_LOG)
	openssl req -new -key $(WEB_KEY) -config $(CONFIG) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Web Server" -rand $(RANDFILE) | openssl x509 -req -inform PEM -outform PEM -CA $(CA_CERT) -CAkey $(CA_KEY) -CAserial $(SERIAL) -extfile $(CONFIG) -extensions websrv_cert -days 365 -sha256 -clrext -out $(WEB_CERT) 2> $(ERROR_LOG)
$(DB_CERT): $(DB_KEY) $(CA_CERT) $(CA_KEY) | $(TLS_DIR) $(SERIAL) $(RANDFILE) $(CONFIG) $(ERROR_LOG)
	openssl req -new -key $(DB_KEY) -config $(CONFIG) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Database Server" -rand $(RANDFILE) | openssl x509 -req -inform PEM -outform PEM -CA $(CA_CERT) -CAkey $(CA_KEY) -CAserial $(SERIAL) -extfile $(CONFIG) -extensions backend_cert -days 365 -sha256 -clrext -out $(DB_CERT) 2> $(ERROR_LOG)
$(BACKUP_CERT): $(BACKUP_KEY) $(CA_CERT) $(CA_KEY) | $(TLS_DIR) $(SERIAL) $(RANDFILE) $(CONFIG) $(ERROR_LOG)
	openssl req -new -key $(BACKUP_KEY) -config $(CONFIG) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Backup Server" -rand $(RANDFILE) | openssl x509 -req -inform PEM -outform PEM -CA $(CA_CERT) -CAkey $(CA_KEY) -CAserial $(SERIAL) -extfile $(CONFIG) -extensions backend_cert -days 365 -sha256 -clrext -out $(BACKUP_CERT) 2> $(ERROR_LOG)
$(CA_TLS_CERT): $(CA_TLS_KEY) $(CA_CERT) $(CA_KEY) | $(TLS_DIR) $(SERIAL) $(RANDFILE) $(CONFIG) $(ERROR_LOG)
	openssl req -new -key $(CA_TLS_KEY) -config $(CONFIG) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Certificate Authority Server" -rand $(RANDFILE) | openssl x509 -req -inform PEM -outform PEM -CA $(CA_CERT) -CAkey $(CA_KEY) -CAserial $(SERIAL) -extfile $(CONFIG) -extensions backend_cert -days 365 -sha256 -clrext -out $(CA_TLS_CERT) 2> $(ERROR_LOG)
$(ARCHIVE_CERT): $(ARCHIVE_KEY) $(CA_CERT) $(CA_KEY) | $(TLS_DIR) $(SERIAL) $(RANDFILE) $(CONFIG) $(ERROR_LOG)
	openssl req -new -key $(ARCHIVE_KEY) -config $(CONFIG) -subj /O="iMovies"/OU="Certificate Archive"/commonName="Archive Encryption Key" -rand $(RANDFILE) | openssl x509 -req -inform PEM -outform PEM -CA $(CA_CERT) -CAkey $(CA_KEY) -CAserial $(SERIAL) -extfile $(CONFIG) -extensions archive_cert -days 3650 -sha256 -clrext -out $(ARCHIVE_CERT) 2> $(ERROR_LOG)	

clean:
	rm -rf $(CA_DIR) $(TLS_DIR)

	