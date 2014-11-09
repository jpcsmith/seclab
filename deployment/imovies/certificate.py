

from .errors import CertificateParsingError
import subprocess
import re as reEngine
from datetime import datetime

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