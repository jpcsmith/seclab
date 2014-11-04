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

class UnexpectedLogicError(SysError):
	""" Exception raised when assumptions of the system do not
	hold true.
	
	This exception is raised when a query which should return
	exactly one result returns less or more.
	
	Attributes:
	  msg (string): explanation of the error
	"""
	
	def __inti__(self, msg):
		self.msg = msg
		
	def __str__(self):
		""" Provide the xml representation of the class """
		return ('<error type="UnexpectedLogicError">'
					'<msg>' + self.msg + '</msg>'
				'</error>')
	
class IssueError