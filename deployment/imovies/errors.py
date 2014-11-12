""" Provides several custom exception classes used by the modules in
the imoviesca package.

"""

class CAError(Exception):
	""" Base exception for exceptions caused by problems with the
	certificate authority system.
	
	Exceptions subclassing this are caused by problems such as I/O
	or invalid configuration, input or logic.
	
	"""
	pass

class InvalidCallError(CAError):
	""" Raised when the format of the script call is invalid. """
	pass


class ConfigError(CAError):
	""" Exception thrown when there is an error processing the 
	configuration file.
	
	"""
	pass
	
	
class CertificateParsingError(CAError):
	""" Exception raised if parsing a certificate fails."""
	pass
	
	
class IssuingError(CAError):
	""" Exception raised when there is an issue with an certificate
	signing request.
	
	"""
	pass

class TooManyIssuedError(CAError):
	""" Thrown when the user tries to issue a certificate when
	they already have one issued. 
	
	"""
	pass

class CertVerificationError(CAError):
	""" Raised when either the procedure to verify a certificate fails.
	
	This should not be raised when the certificate is revoked or expired.
	
	"""
	pass


class InvalidCertError(CAError):
	""" Raised when a certificate proves to be either expired or revoked. """
	pass

class InvalidSerialFileError(CAError):
	""" Raised when the serial cannot be read from the serial file. """
	pass

class RevocationError(CAError):
	""" Raised when revocation of a certificate cannot be done. """
	pass

class CRLGenerationError(CAError):
	""" Raised when the CRL generation fails """
	pass
	