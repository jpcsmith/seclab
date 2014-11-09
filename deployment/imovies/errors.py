""" Provides several custom exception classes used by the modules in
the imoviesca package.
"""

from mysql.connector.errors import Error as MySQLError

class CAError(Exception):
	""" Base exception for exceptions caused by problems with the
	certificate authority system.
	
	Exceptions subclassing this are caused by problems such as I/O
	or invalid configuration, input or logic.
	"""
	pass

class ConfigError(CAError):
	""" Exception thrown when there is an error processing the 
	configuration file.
	
	Attributes:
	  msg (string): explanation of the error
	"""
	
	def __init__(self, msg):
		self.msg = msg
		
	def __str__(self):
		""" Provide the xml representation of the class """
		return ('<error type="ConfigError">'
					'<msg>' + self.msg + '</msg>'
				'</error>')
	
class CertificateParsingError(CAError):
	""" Exception raised if parsing a certificate fails.
	
	Attributes:
	  msg (string): explanation of the errors
	  
	"""
	def __inti__(self, msg):
		self.msg = msg
		
	def __str__(self):
		""" Provide the xml representation of the class """
		return ('<error type="CertificateParsingError">'
					'<msg>' + self.msg + '</msg>'
				'</error>')
	
class IssuingError(CAError):
	""" Exception raised when there is an issue with an certificate
	signing request.
	
	Attributes:
	  msg (string): an explanation of the error
	  
	"""
	def __init__(self, msg):
		self.msg = msg
		
	def __str__(self):
		""" Provide the xml representation of the class """
		return ('<error type="IssuingError">'
					'<msg>' + self.msg + '</msg>'
				'</error>')

def str(err):
	""" Returns an xml string representation of a mysql.connector.errors.Error
	exception.
	
	Args:
	  err (mysql.connector.errors.Error): The exception to return the xml 
	    representation of.
	    
	"""
	return ('<error type="MySQLError">'
				'<msg>' + err.msg + '</msg>'
			'</error>')
			