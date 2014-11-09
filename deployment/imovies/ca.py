""" """
# TODO Note that the infrastructure Certs are not in the database
# Note: May skip serial numbers



from .errors import IssuingError, ConfigError, UnexpectedLogicError, CertificateParsingError
from .dbaccess import DBConnector
import logging
from . import errors
from mysql.connector.errors import Error as MySQLError
import subprocess
import configparser
import re as reEngine
from tempfile import NamedTemporaryFile
from datetime import datetime

class CertificateAuthority:
	""" """
	
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
			self.daysToCert = config.get(ca_section, 'default_days', fallback = '365')
			self.digest = config.get(ca_section, 'default_md', fallback = 'sha512')
			self.extensionSect = config.get(ca_section, 'x509_extensions')
		except configparser.Error as err:
			raise ConfigError('Problem reading the CA settings from '
				'the configuration file.') from err
		else:
			self.opensslConfig = settingsFile;
			self.db = DBConnector(settingsFile)

	
	def issueCert(self, uid, pHash):
		""" Issues a new certificate to the user specified by uid.
		
		TODO Overview of the method
		  
		  
		  
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
				raise IssuingError('The user already has an issued certificate. '
					'Please first revoke that certificate.')
			
			# Get the client's information
			lname, fname, email = self.db.getEmployeeAtr(uid)
			
			# Create the private key, request and certificate
			privateKey, csr = self._req(uid, lname, fname, email)
			cert = self._sign(csr)
			
			# TODO encrypt the private key for storage
			encPrivateKey = privateKey
			
			# Store the certificate and key in the database
			self.db.storeCert(uid, cert, encPrivateKey)
			
			
		except (MySQLError, IssuingError) as err:
			logging.exception(err.msg)
			raise
		finally:
			self.db.close()
		return cert

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
							stderr = subprocess.PIPE, universal_newlines = True);
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
		
		
class Certificate:
	""" Class representing an issued certificate.
	
	Attributes:
	  encoding (string): The PEM fromatted encoding of the certificate passed 
	    in the constructor.
	  serial (string): The certificate serial number, in hexadecimal, without 
	    the leading '0x'
	  subject (string): The one-line openssl encoding of the subject,e.g.:
	    /O=iMovies/OU=TLS Infrastructure/CN=Backup Server
	  expiryDate (datetime.datetime): The date at which the certificate is to 
	    expiry. The stored date & time is UTC.
	    
	"""
	def __init__(self, cert):
		""" Initialise the certificate by parsing needed attributes
		from the PEM encoding. 
		
		Raises:
		  CertificateParsingError: If unable to parse the certificate
		    from the proviced string.
		"""
		self.encoding = cert
		# Fetch the serial number and expiry date from the cert
		process = subprocess.Popen(['openssl', 'x509', '-noout', 
							  '-enddate', '-serial', '-subject'], 
							 stdin = subprocess.PIPE, stdout = subprocess.PIPE, 
							 stderr = subprocess.DEVNULL, universal_newlines = True);
		stdout, stderr = process.communicate(cert)
		if process.returncode != 0:
			raise CertificateParsingError('Unable to parse the certificate. '
				'Openssl reason: %s' % stderr)
		
		# Get and assign the subject string
		pattern = '^subject=(?P<subject>.+)$'
		match = reEngine.search(pattern, stdout, flags = reEngine.IGNORECASE | reEngine.MULTILINE)
		self.subject = match.group(1).strip()
		
		# Get and assign the serial number
		pattern = '^serial=(?P<serial>.+)$'
		match = reEngine.search(pattern, stdout, flags = reEngine.IGNORECASE | reEngine.MULTILINE)
		self.serial = match.group(1) # Hex string
		
		# Get and assign the expiry datetime
		pattern = '^notAfter=(?P<datetime>.+)$'
		match = reEngine.search(pattern, stdout, flags = reEngine.IGNORECASE | reEngine.MULTILINE)
		self.expiryDate = datetime.strptime(match.group(1), '%b %d %H:%M:%S %Y %Z')