# Directories
CA_DIR		= ../CA
NCERTS_DIR	= $(CA_DIR)/newcerts
KEY_DIR		= $(CA_DIR)/private
PKI_DIR		= ../PKI

# Files
SERIAL 		= $(CA_DIR)/serial
ISSUED		= $(CA_DIR)/index.txt
CNF		= $(CA_DIR)/imoviesca.cnf
TEMP_CSR	= temp.csr

# Server cert & private key
CA_CERT		= $(CA_DIR)/ca_cert.pem
CA_KEY		= $(KEY_DIR)/ca_key.pem

# Other certs & private keys
WEB_CERT	= $(PKI_DIR)/web_cert.pem
WEB_KEY		= $(PKI_DIR)/web_key.pem
DB_CERT		= $(PKI_DIR)/db_cert.pem
DB_KEY		= $(PKI_DIR)/db_key.pem
BACKUP_CERT	= $(PKI_DIR)/backup_cert.pem
BACKUP_KEY	= $(PKI_DIR)/backup_key.pem
CA_NR_CERT	= $(CA_DIR)/ca_nr_cert.pem
CA_NR_KEY	= $(KEY_DIR)/ca_nr_key.pem

CERTS		:= $(CA_CERT) $(WEB_CERT) $(DB_CERT) $(BACKUP_CERT) $(CA_NR_CERT)

# Deployment files
DEP_CNF		= imoviesca.cnf
DEP_PKG		= imovies

.PHONY: clean all
.SILENT:

all: $(CERTS)

# Directory setup
$(CA_DIR):
	mkdir $(CA_DIR)
$(PKI_DIR):
	mkdir $(PKI_DIR)
$(NCERTS_DIR):
	mkdir -p $(NCERTS_DIR)
$(KEY_DIR):
	mkdir -p $(KEY_DIR)
	
# File setup
$(SERIAL): | $(CA_DIR)
	echo "01" > $(SERIAL)
$(ISSUED): | $(CA_DIR)
	touch $(ISSUED)
$(CNF): | $(CA_DIR) $(DepCNF)
	cp $(DEP_CNF) $(CNF)

# PKI setup
$(WEB_KEY): | $(PKI_DIR)
	openssl genrsa -out $(WEB_KEY) 2048
$(DB_KEY): | $(PKI_DIR)
	openssl genrsa -out $(DB_KEY) 2048
$(BACKUP_KEY): | $(PKI_DIR)
	openssl genrsa -out $(BACKUP_KEY) 2048
$(CA_NR_KEY): | $(PKI_DIR)
	openssl genrsa -out $(CA_NR_KEY) 2048
	
$(WEB_CERT): $(WEB_KEY) $(CA_CERT) $(CA_KEY) | $(PKI_DIR) $(SERIAL) $(ISSUED) $(NCERTS_DIR)
	openssl req -new -config $(CNF) -key $(WEB_KEY) -out $(TEMP_CSR) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Web Server"
	openssl ca -in $(TEMP_CSR) -extensions websrv_cert -policy srv_policy -config $(CNF) -out $(WEB_CERT) -batch
	rm $(TEMP_CSR)
$(DB_CERT): $(DB_KEY) $(CA_CERT) $(CA_KEY) | $(PKI_DIR) $(SERIAL) $(ISSUED) $(NCERTS_DIR)
	openssl req -new -config $(CNF) -key $(DB_KEY) -out $(TEMP_CSR) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Database Server"
	openssl ca -in $(TEMP_CSR) -extensions backend_cert -policy srv_policy -config $(CNF) -out $(DB_CERT) -batch
	rm $(TEMP_CSR)
$(BACKUP_CERT): $(BACKUP_KEY) $(CA_CERT) $(CA_KEY) | $(PKI_DIR) $(SERIAL) $(ISSUED) $(NCERTS_DIR)
	openssl req -new -config $(CNF) -key $(BACKUP_KEY) -out $(TEMP_CSR) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Backup Server"
	openssl ca -in $(TEMP_CSR) -extensions backend_cert -policy srv_policy -config $(CNF) -out $(BACKUP_CERT) -batch
	rm $(TEMP_CSR)
$(CA_NR_CERT): $(CA_NR_KEY) $(CA_CERT) $(CA_KEY) | $(PKI_DIR) $(SERIAL) $(ISSUED) $(NCERTS_DIR)
	openssl req -new -config $(CNF) -key $(CA_NR_KEY) -out $(TEMP_CSR) -subj /O="iMovies"/OU="TLS Infrastructure"/commonName="Certificate Authority Server"
	openssl ca -in $(TEMP_CSR) -extensions backend_cert -policy srv_policy -config $(CNF) -out $(CA_NR_CERT) -batch
	rm $(TEMP_CSR)

$(CA_KEY): | $(KEY_DIR)
	openssl genrsa -out $(CA_KEY) 4096	# May need to set the rand here
$(CA_CERT): $(CA_KEY) | $(CA_DIR) $(CNF)
	openssl req -new -x509 -days 3650 -key $(CA_KEY) -out $(CA_CERT) -subj /O="iMovies"/OU="PKI Infrastructure"/commonName="Certificate Authority" -config $(CNF)

clean:
	rm -rf $(CA_DIR) $(PKI_DIR)
