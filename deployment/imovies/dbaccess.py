""" Handles database connection and access for the Certificate Authority.

This module primarily provides the DBConnector class which is used to
connect to and transact with the database. 

Security:
  Prepared statements: Queries use prepared statements when providing input.

"""

from .errors import ConfigError, UnexpectedLogicError
import configparser, mysql.connector, logging

class DBConnector:
	""" Facilitates connections to and interactions with the database.
	
	DBConnector is responsible for maintaining the connection to the database
	as well as reading 
	
	"""
	
	def __init__(self):
		""" Initialise the DBConnector by reading connections settings
		from the settings file.
		
		Raises:
		  ConfigError: If unable to retrieve the configuration information
		    from the settings file.
		    
		"""
		# TODO Adjust to connect using SSL
		try: 
			# Parse the configuration file
			config = configparser.ConfigParser(allow_no_value = False)
			config.read('settings.cfg')
			
			# Read the config information for the connection
			self.user = config['MySQL']['user']
			self.database = config['MySQL']['database']
			self.host = config['MySQL']['host']
			self.port = config['MySQL']['port']
		except configparser.Error as err:
			raise ConfigError('Problem reading database settings from '
				'the configuration file.') from err
		except KeyError as err:
			raise ConfigError('One or more fields required for the database '
				'connection are missing in the settings file.') from err
	
	def connect(self):
		""" Connect to the database.
		
		Raises:
		  mysql.connector.errors.Error: If the connection attempt fails.
		"""
		self._connection = mysql.connector.connect(
			user = self.user, database = self.database, 
			host = self.host, port = self.port, raw=False)
	
	def close(self):
		""" Close the database connection. """
		self._connection.close()
	
# ----- Functions that wrap the database access
	
	def getEmployeeAtr(self, uid):
		""" Retrieve employee attributes from the database.
		
		This method retrieves the employee attributes from the database
		corresponding to the supplied user id and hash value.
		
		Args:
		  uid (string): The user id of the user whose attributes should
		    be fetched.
		  pHash (string): The SHA1-checksum of the user's password.
		  
		Returns:
		  { }: A dictionary containing the user's attributes.
		  
		  The dictionary's keys are 'uid' for the user's id, 'lname' for
		  the user's last name, 'fname' for his/her first name and 'email'
		  for their email address.
		  
		Raises:
		  mysql.connector.errors.Error: If the select query fails.
		  
		"""
		resultDict = { }
		# Prepare the statement and data
		statement = ('SELECT uid, lastname, firstname, email '
			'FROM users WHERE uid=%s')
		# Wrap in try finally to ensure the cursor is closed
		try:
			# Execute the statement and fetch the results
			cursor = self._connection.cursor(prepared = True)
			cursor.execute(statement, (uid,))
			(uid, lname, fname, email) = cursor.fetchone()
			
			resultDict = { 'uid': bytes(uid), 'lname':bytes(lname), 
				 'fname':bytes(fname), 'email':bytes(email) }
		finally:
			cursor.close()
		return resultDict
	
	
	def ensureAuthCall(self, uid, token):
		""" Verify that the user id and token match a value that is stored in
		the database. 
		
		This method checks the user id and token (user password hash) to ensure
		that they are in deed in the database. This method should be called at
		the start of each routine to enforce the presence of the user password
		hash as an authentication token for the call.
		
		Args:
		  uid (string): The user's user id
		  token (string): The SHA1-checksum of the user's password
		  
		Returns:
		  bool: True if the passed uid, token pair exist in the users table of
		    the database, false otherwise.
		
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		# Preapre the statement and data
		statement = 'SELECT EXISTS(SELECT 1 FROM users WHERE uid=%s AND pwd=%s)'
		data = (uid, token)
		
		try:
			cursor = self._connection.cursor(prepared = True)
			cursor.execute(statement, data)
			resultTuple = cursor.fetchone()
			
			exists = 1 in resultTuple
		finally:
			cursor.close()
		return exists
	
	
	def hasIssued(self, uid):
		""" Checks if the user already has a certificate issued.
		
		Args:
		  uid (string): The user's user id
		  
		Returns:
		  bool: True if the user with id, uid, has a certificate issued and
		    stored in the database, False otherwise.
		
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		statement = 'SELECT EXISTS(SELECT 1 FROM user_certs WHERE uid=%s)'
		try:
			cursor = self._connection.cursor(prepared = True)
			cursor.execute(statement, (uid,))
			resultTuple = cursor.fetchone()
			
			exists = 1 in resultTuple
		finally:
			cursor.close()
		return exists