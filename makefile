# Directories
# CA_DIR is taken from the environment
CERTS_DIR =	$(CA_DIR)/certs
NCERTS_DIR =	$(CA_DIR)/newcerts
KEY_DIR =	$(CA_DIR)/private
DEPLOY =	$(DIR)/deployment

# Files
SERIAL =	$(CA_DIR)/serial
ISSUED =	$(CA_DIR)/index.txt
CNF =		$(CA_DIR)/openssl.cnf

# Server cert & private key
CA_CERT =	$(CA_DIR)/ca_cert.pem
CA_KEY =	$(KEY_DIR)/ca_key.pem

# Deployment files
DepCNF =	$(DEPLOY)/openssl.cnf

.PHONY: clean test
.SILENT:

# Directory creation
$(CA_DIR):
	mkdir $(CA_DIR)
$(CERTS_DIR): | $(CA_DIR)
	mkdir $(CERTS_DIR)
$(NCERTS_DIR): | $(CA_DIR)
	mkdir $(NCERTS_DIR)
$(KEY_DIR): | $(CA_DIR)
	mkdir $(KEY_DIR)
	
# File creation
$(SERIAL): | $(CA_DIR)
	echo "01" > $(SERIAL)
$(ISSUED): | $(CA_DIR)
	touch $(ISSUED)
$(CNF): | $(CA_DIR) $(DepCNF)
	cp $(DepCNF) $(CA_DIR)

$(CA_KEY): | $(KEY_DIR)
	openssl genrsa -out $(CA_KEY) 4096	# May need to set the rand here
$(CA_CERT): $(CA_KEY) | $(CA_DIR)
	openssl req -new -x509 -days 3650 -key $(CA_KEY) -sha256 -out $(CA_CERT) -subj /O="iMovies"/OU="PKI Infrastructure"/commonName="Certificate Authority" -config ./skel.cnf
	
test: $(CA_CERT)

clean:
	rm -rf $(CA_DIR)
