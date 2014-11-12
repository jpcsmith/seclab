

import os, base64, logging
import subprocess, configparser
import re as reEngine
from . import errors
from .certificate import Certificate
from mysql.connector.errors import Error as MySQLError
from .errors import IssuingError, ConfigError, CertVerificationError, RevocationError
from .errors import CertificateParsingError, InvalidCertError, InvalidSerialFileError
from .errors import CRLGenerationError, TooManyIssuedError
from .dbaccess import DBConnector
from tempfile import NamedTemporaryFile


class CertificateAuthority:
	""" Models a certificate authority. 
	
	Attributes:
	  serialFile (string): Path to the file containing the next serial # to issue
	  privateKeyFile (string): Path to the CA private key file
	  certificateFile (string): Path to the CA certificate file
	  archiveCert (string): Path to the archive certificate
	  daysToCert (string): Days to certify for
	  digest (string): Default digest to use
	  extensionSect (string): x509 extensions section in the config file
	  rand (string): Path to the rand file of the os
	  opensslConfig (string): Path to the config file
	  db (imovies.dbaccess.DBConnector): The connector handing the database IO
	
	"""
	
	def __init__(self, settingsFile):
		""" Create a new CertificateAuthority object using the specified
		settings file.
		
		Args:
		  settingsFile (string): The file name of the settings file for
		    the certificate authority.
		
		Raises:
		  ConfigError: If unable to retrieve the configuration information
		    from the settings file.
		    
		"""
		try: 
			# Parse the configuration file
			config = configparser.ConfigParser(allow_no_value = False,
						interpolation = configparser.ExtendedInterpolation(),
						inline_comment_prefixes = ('#',';'))
			# Change the regex to allow spaces in the section name
			config.SECTCRE = reEngine.compile(r"\[ *(?P<header>[^]]+?) *\]")
			config.read(settingsFile)

			ca_section = config.get('ca', 'default_ca')
			self.serialFile = config.get(ca_section, 'serial')
			self.privateKeyFile = config.get(ca_section, 'private_key')
			self.certificateFile = config.get(ca_section, 'certificate')
			self.indexFile = config.get(ca_section, 'database')
			self.crlFile = config.get(ca_section, 'crl')
			self.archiveCert = config.get(ca_section, 'archive_cert')
			self.daysToCert = config.get(ca_section, 'default_days', fallback = '365')
			self.digest = config.get(ca_section, 'default_md', fallback = 'sha512')
			self.extensionSect = config.get(ca_section, 'x509_extensions')
			self.rand = config.get(ca_section, 'rand')
		except configparser.Error as err:
			raise ConfigError('Problem reading the CA settings from '
				'the configuration file.') from err
		else:
			self.opensslConfig = settingsFile;
			self.db = DBConnector(settingsFile)

	
	def issueCert(self, uid, pHash):
		""" Issues a new certificate to the user specified by uid.
		
		This method operates as follows: connects to the database -> ensures
		the uid, pHash matches a stored user -> updates the database to mark
		expired certificates -> checks if the user has any valid certificates
		-> get the employee's attributes -> generate the private key and CSR
		-> sign the CSR -> pack the private key and cert in PKCS#12 -> encrypt
		the private key for storage -> archive the private key and certificate
		-> post the issued certificate to the database.
		
		If any one of these procedures fail, the certificate is not issued. This
		means that there may be stored certificates in the archive that have not
		been issued as the MyISAM database does not support transactions.
		
		Args:
		  uid (string): The uid of the employee to issue the cert to.
		  pHash (string): The SHA1 hash of the user's password to verify
		    the operation.
		    
		Returns:
		  string: A PKCS#12 base64 encoded string containing the private key
		  and certificate issued.
		
		Raises:
		  IssuingError: If the certificate cannot be issued due to a fault
		    in the CA's system or program.
		  TooManyIssuedError: If the user has too many certificates issued
		  mysql.connector.errors.Error: If the certificate cannot be issued
		    due to a problem with the database.
		  
		"""
		try:
			# Connect to the database
			self.db.connect()
			
			# Do the call authentication check
			if not self.db.ensureAuthCall(uid, pHash):
				raise IssuingError('The user id, token combination is not valid')
			
			# Update the databases to account for expired certificates
			self.db.updateExpiredCerts()
			
			# Ensure that the employee does not have a certificate issued
			if self.db.hasIssued(uid):
				raise TooManyIssuedError('The user already has an issued certificate. '
					'Please first revoke that certificate.')
			
			# Get the client's information
			_, lname, fname, email = self.db.getEmployeeAtr(uid)
			
			# Create the private key, request and certificate
			privateKey, csr = self._req(uid, lname, fname, email)
			try:
				cert = self._sign(csr)
			except CertificateParsingError as err:
				raise IssuingError('Unable to issue the certificate due to an '
					'internal parsing error, this should never happen.') from err
			
			# Create the PKCS#12 bundle of the key and cert
			packName = '%s, %s | iMovies' % (lname, fname)
			pfx = self._toPKCS12(packName, cert, privateKey)
			
			# Encrypt the private key
			encIV, encSymKey, salt, encPrivateKey = self._encryptKey(privateKey)
			
			# Archive the private key
			self.db.archiveCert(cert, encPrivateKey, encIV, encSymKey, salt)
			
			""" Store the certificate and key in the database.
			We do this last so that at this point we are certain we have
			the product to return to the caller. If this fails, we dont
			have to return anything.
			"""
			self.db.storeCert(uid, cert)
		finally:
			self.db.close()
		return pfx


	def _req(self, cn, sn, gn, email):
		""" Generates a private key and certificate signing request (CSR) 
		for the supplied credentials. 
		
		Args:
		  cn (string): The employee's user id, uid
		  sn (string): The employee's surname
		  gn (string): The employee's given name
		  email (string): The employee's email address
		
		Returns:
		  (privateKey, csr): A tuple containing the generated private key and
		  certificate signing request. Both are strings encoded in PEM format,
		  with the private key using PKCS#8 syntax.
		
		Raises:
		  IssuingError: if the attempt to generate the private key
		    and CSR fails.
		
		"""
		# Create the string containing the values to be in the cert request
		subject = ('/O=iMovies/OU=Employee Base/SN=%s/GN=%s'
			'/commonName=%s/emailAddress=%s') % (sn, gn, cn, email)
		
		# Use the openssl ca to sign the file 
		process = subprocess.Popen(['openssl', 'req', '-new', '-batch', 
							  '-inform', 'PEM', '-outform', 'PEM',
							  '-newkey', 'rsa', 
							  '-subj', subject,
							  '-rand', self.rand,
							  '-config', self.opensslConfig], 
							stdin = subprocess.DEVNULL, stdout = subprocess.PIPE, 
							stderr = subprocess.PIPE, universal_newlines = True);
		stdout, stderr = process.communicate()
		
		# Expect a return code of zero for successful execution
		if process.returncode != 0:
			raise IssuingError('Unable to create the certificate request. '
				'Openssl reason: %s' % stderr)
		else:
			# Seperate the private and public keys
			pattern = ('.*(?P<privateKey>-----BEGIN PRIVATE KEY-----'
				'.+-----END PRIVATE KEY-----)'
				'.*(?P<csr>-----BEGIN CERTIFICATE REQUEST-----'
				'.+-----END CERTIFICATE REQUEST-----)')
			match = reEngine.match(pattern, stdout, flags = reEngine.IGNORECASE | reEngine.DOTALL)
			logging.info('Created a CSR for employee with uid %s', cn)
			return match.groups()

	
	def _sign(self, csr):
		""" Sign a certificate signing request.
		
		The options used include:
		  - Input and output format are PEM
		  - Extensions are dropped from the request
		
		Args:
		  csr (string): A certificate signing request in PEM format.
		  
		Returns:
		  imovies.ca.Certificate: A certificate object containing the
		  signed certificate.
		  
		Raises:
		  IssuingError: If the signing failed. The message of the error 
		    contains the openssl error output.
		  CertificateParsingError: If the parsing of the created certificate
		    fails.
		
		"""
		# Sign the certificate from the CSR
		process = subprocess.Popen(['openssl', 'x509', '-req',
							  '-inform', 'PEM', '-outform', 'PEM',
							  '-CA', self.certificateFile, '-CAkey', self.privateKeyFile,
							  '-CAserial', self.serialFile,
							  '-extfile', self.opensslConfig, 
							  '-extensions', self.extensionSect,
							  '-days', self.daysToCert,
							  '-%s' % self.digest, '-clrext'],
							stdin = subprocess.PIPE, stdout = subprocess.PIPE, 
							stderr = subprocess.PIPE, universal_newlines = True)
		stdout, stderr = process.communicate(csr)
		# Expect a return code of zero for successful execution
		if process.returncode != 0:
			raise IssuingError('Unable to sign the certificate. '
				'Openssl reason: %s' % stderr)
		else:
			# Create a certificate object
			certif = Certificate(stdout)
			logging.info('Signed a new certificate with serial number %s', 
				certif.serial)
			return certif
	
	
	def _encryptKey(self, privateKey):
		""" Encrypts the private key using AES-256-CBC and the RSA based on the
		archive's certificate.
		
		Args:
		  privateKey (string): The private key to encrypt.
		
		Returns:
		  (encIV, encSymKey, salt, encPrivKey): A 4-tuple containing the 
		  initialization vector and AES key, RSA encrypted under the archive's 
		  certificate and base64 encoded in a string, the initialization salt 
		  as a hex string and the private key encrypted under AES in a base64
		  string.
		  
		Raises:
		  IssuingError: If the encryption failed. The message of the error 
		    contains the openssl error output.
		
		"""
		# Generate a salt, key and IV for AES encryption
		randomString = str(base64.standard_b64encode(os.urandom(32)), 'UTF-8') 
		process = subprocess.Popen(['openssl', 'enc', '-e', '-aes-256-cbc', 
							  '-pass', 'pass:%s' % randomString, '-P'],
							stdin = subprocess.PIPE, stdout = subprocess.PIPE,
							stderr = subprocess.PIPE, universal_newlines = True)
		stdout, stderr = process.communicate()
		if process.returncode != 0:
			raise IssuingError('Unable to generate a symmetric key for key management. '
				'Openssl reason: %s' % stderr)
		pattern = '.*(?:iv =(?P<iv>[a-fA-F0-9]+)\n|salt=(?P<salt>[a-fA-F0-9]+)\n|key=(?P<key>[a-fA-F0-9]+)\n){3}'
		match = reEngine.search(pattern, stdout, flags = reEngine.IGNORECASE | reEngine.DOTALL)
		aesDict = match.groupdict()
		
		# Encrypt the private key using the symmetric key
		process = subprocess.Popen(['openssl', 'enc', '-e', '-aes-256-cbc', 
							  '-S', aesDict['salt'], '-iv', aesDict['iv'],
							  '-K', aesDict['key'], '-base64'],
							stdin = subprocess.PIPE, stdout = subprocess.PIPE,
							stderr = subprocess.PIPE, universal_newlines = True)
		stdout, stderr = process.communicate(privateKey)
		if process.returncode != 0:
			raise IssuingError('Unable to encrypt the private key for key management. '
				'Openssl reason: %s' % stderr)
		aesDict['encPrivKey'] = stdout
		
		# Encrypt the symmetric key using the archive cert
		process = subprocess.Popen(['openssl', 'rsautl', '-encrypt', '-certin', 
							  '-inkey', self.archiveCert],
							stdin = subprocess.PIPE, stdout = subprocess.PIPE, 
							stderr = subprocess.PIPE)
		stdout, stderr = process.communicate(bytes(aesDict['key'], 'UTF-8'))
		# Expect a return code of zero for successful execution
		if process.returncode != 0:
			raise IssuingError('Unable to encrypt the symmetric key for storage. '
				'Openssl reason: %s' % stderr)
		aesDict['encSymKey'] = str(base64.standard_b64encode(stdout), 'UTF-8')
		
		# Encrypt the initialization vector using the archive cert
		process = subprocess.Popen(['openssl', 'rsautl', '-encrypt', '-certin', 
							  '-inkey', self.archiveCert],
							stdin = subprocess.PIPE, stdout = subprocess.PIPE, 
							stderr = subprocess.PIPE)
		stdout, stderr = process.communicate(bytes(aesDict['iv'], 'UTF-8'))
		# Expect a return code of zero for successful execution
		if process.returncode != 0:
			raise IssuingError('Unable to encrypt the initialization vector for storage. '
				'Openssl reason: %s' % stderr)
		aesDict['encIV'] = str(base64.standard_b64encode(stdout), 'UTF-8')
		
		return (aesDict['encIV'], aesDict['encSymKey'], aesDict['salt'], aesDict['encPrivKey'])
		

	def _toPKCS12(self, name, certificate, privateKey):
		""" Converts a PEM certificate and PEM private key to a PKCS#12 bundle.
		
		Args:
		  name (string): A friendly name to apply to the PKCS#12 bundle.
		  certificate (imovies.certificate.Certificate): A certificate issued
		    by the CA.
		  privateKey (string): A PEM encoded private key corresponding to the
		    supplied certificate.
		
		Returns:
		  string: The PKCS12 container encoded in base64
		
		Raises:
		  IssuingError: If the packaging failed. The message of the error 
		    contains the openssl error output
		
		"""
		process = subprocess.Popen(['openssl', 'pkcs12', '-export', '-name', name, 
							  '-passout', 'pass:'],
							stdin = subprocess.PIPE, stdout = subprocess.PIPE, 
							stderr = subprocess.PIPE)#, universal_newlines = True)
		# We change it to a byte stream because the newline was causing problems
		# as a string.
		data = (privateKey + '\n' + certificate.encoding).encode()
		stdout, stderr = process.communicate(data)
		if process.returncode != 0:
			raise IssuingError('Unable to bundle as PKCS#12. Openssl reason: %s' 
				% stderr)
		else:
			return str(base64.standard_b64encode(stdout), 'UTF-8')


	def getStatistics(self, certString):
		""" Get CA statistics for use by the CA administrator.
		
		Returns:
		  (int, int, string): A tuple consisting of the number of issued certificates,
		  the number of revoked certificates and a hex string of the current serial 
		  number.
		
		Raises:
		  CertificateParsingError: If unable to parse the admin's certificate.
		  InvalidCertError: If the certificate is expired or revoked or does not belong
		    to an admin.
		  CertVerificationError: If the verification procedure fails for some reason.
		  mysql.connector.errors.Error: If the there is a problem with the database.
		  
		"""
		try:
			# Connect to the database
			self.db.connect()
				
			adminCert = Certificate(certString)
			
			# Check that the certificate is valid and not revoked or expired
			self._verifyCertificate(adminCert)
			
			# Ensure that the user is an admin
			if not self.db.isAdmin(adminCert.serial):
				raise InvalidCertError('The certificate was not issued to a '
					'certificate authority administrator.')
			
			# Get the statistics
			nIssued = self.db.getNIssued()
			nRevoked = self.db.getNRevoked()
			nextSerial = self._getNextSerial(self.serialFile)
			
			return (nIssued, nRevoked, nextSerial)
		finally:
			self.db.close()
		
		
	def _verifyCertificate(self, certificate):
		""" Verifies that the provided certificate is valid.
		
		Args:
		  certificate (imovies.certificate.Certificate): The certificate to verify
		
		Returns:
		  bool: True if the certificate is valid.
		
		Raises:
		  InvalidCertError: If the certificate is expired or revoked
		  CertVerificationError: If the verification procedure fails
		    for some reason.
		"""
		with NamedTemporaryFile('w+t') as joinedFile:
			# Concatenate the CA Cert and CRL otherwise -crl_check fails
			for fname in (self.certificateFile, self.crlFile):
				with open(fname) as infile:
					joinedFile.write(infile.read())
			joinedFile.flush()
		
			process = subprocess.Popen(['openssl', 'verify', '-crl_check',
								'-CAfile', joinedFile.name],
								stdin = subprocess.PIPE, stdout = subprocess.PIPE,
								stderr = subprocess.PIPE, universal_newlines = True)
			stdout, stderr = process.communicate(certificate.encoding)
		
		if process.returncode != 0:
			raise CertVerificationError('The verification procedure failed. '
				'Openssl reason: %s | %s' % (stdout, stderr))
		
		# A successful verification is marked by 'stdin: OK' being printed in stdout
		pattern = '^stdin: OK$'
		match = reEngine.search(pattern, stdout, flags = reEngine.IGNORECASE | reEngine.DOTALL)
		if match:
			return True
		
		# Otherwise we can assume it failed, just to determine the kind of error
		pattern = '(.*error ([0-9]+) at 0 depth)+'
		match = reEngine.search(pattern, stdout, flags = reEngine.IGNORECASE | reEngine.DOTALL)
		if not match:
			raise CertVerificationError('The verification procedure failed. '
				'Openssl reason: %s | %s' % (stdout, stderr))
		else:
			# Codes that mean revoked or expired - 23, 10
			for errno in match.groups():
				if int(errno) == 23 or int(errno) == 10:
					raise InvalidCertError('The certificate is either revoked or invalid. '
						'Openssl reason: %s | %s' % (stdout, stderr))
				else:
					raise CertVerificationError('The verification procedure failed. '
						'Openssl reason: %s | %s' % (stdout, stderr))


	def _getNextSerial(self, fileAddress):
		""" Retrieves the next serial number from the serial file.
		
		Returns:
		  string: The serial number as a hex string.
		
		Raises:
		  OSError: If the file cannot be read
		  InvalidSerialFileError: If the serial cannot be read from the file
		  
		"""
		with open(fileAddress, 'r') as sFile:
			serialLine = sFile.readline()
			
		pattern = '^(?P<serialNo>[0-9a-fA-F]+)$'
		match = reEngine.search(pattern, serialLine, flags = reEngine.IGNORECASE)
		if not match:
			raise InvalidSerialFileError('A valid serial number could not be read '
				'from the file.')
		else:
			serialNo = int(match.groupdict()['serialNo'], 16)
			if serialNo == 0:
				raise InvalidSerialFileError('Invalid serial number of 0 read.')
			else:
				return match.groupdict()['serialNo']
	
	
	def revokeCert(self, uid = None, pHash = None, certificate = None):
		""" Revokes a still valid user certificate.
		
		Either the uid and pHash OR the certificate should be provided.
		
		Args:
		  uid (string): The user id of the the user
		  pHash (string): The SHA1 hash of the user's password
		  certificate: The user's certificate to revoke
		
		Returns:
		  string: A new CRL PEM encoded in the event that the operation succeeds.
		
		Raises:
		  CertificateParsingError: If unable to parse the admin's certificate.
		  InvalidCertError: If the certificate is expired or revoked or does not belong
		    to an admin.
		  CertVerificationError: If the verification procedure fails for some reason.
		  mysql.connector.errors.Error: If the there is a problem with the database.
		  
		"""
		try:
			# Connect to the database
			self.db.connect()
		
			if uid is not None and pHash is not None:
				# Ensure authenticate uid and passwrod
				if not self.db.ensureAuthCall(uid, pHash):
					raise RevocationError('The user id, token combination is not valid')
				# Get the associated serial
				serial = self.db.getIssuedSerial(uid)
				if serial is None:
					raise RevocationError('The user has no certificates to revoke.')
			else:
				userCert = Certificate(certString)
				# Verify the certificate
				self._verifyCertificate(userCert)
				serial = userCert.serial
			
			# Revoke the certificate with that serial
			self.db.markRevoked(serial)
		finally:
			self.db.close()
	
	
	def generateCRL(self):
		""" Generates a signed certificate revocation list.
		
		Returns:
		  string: A CRL in PEM format.
		  
		Raises:
		  OSError: If the local index cannot be updated or the crl cannot be written
		    locally
		  CRLGenerationError: if crl generation fails.
		  mysql.connector.errors.Error: If the there is a problem with the database.
		  
		"""
		try:
			# Connect to the database
			self.db.connect()
		
			# Update the local database
			self.db.updateLocalIndex(self.indexFile)
			
			process = subprocess.Popen(['openssl', 'ca', '-gencrl', 
								'-config', self.opensslConfig,],
								stdin = subprocess.PIPE, stdout = subprocess.PIPE,
								stderr = subprocess.PIPE, universal_newlines = True)
			stdout, stderr = process.communicate()
			if process.returncode != 0:
				raise CRLGenerationError('Unable to generate a CRL. '
					'Openssl reason: %s' % stderr)
			
			# Write it to the local CRL file
			with open(self.crlFile, 'w') as localCRLFile:
				localCRLFile.write(stdout)
			
			# Add the CRL file to the database
			self.db.storeCRL(stdout)
			
			return stdout
		finally:
			self.db.close()