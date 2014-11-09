""" Handles database connection and access for the Certificate Authority.

This module primarily provides the DBConnector class which is used to
connect to and transact with the database. 

Security:
  Prepared statements: Queries DO NOT use prepared statements when providing input.
  This is because apparently when using PARAMERTIZED queries, variables are escaped.

TODO ADD CIPHERS!!!
"""

from .errors import ConfigError
import configparser, mysql.connector, logging
import re as regex
from .certificate import Certificate
import io

class DBConnector:
	""" Facilitates connections to and interactions with the database.
	
	DBConnector is responsible for maintaining the connection to the database
	as well as reading and modifying the various tables of the database.
	
	"""
	
	def __init__(self, settingsFile):
		""" Initialise the DBConnector by reading connections settings
		from the settings file.
		
		Args:
		  settingsFile (string): The file name of the settings file containing
		    the database connection information.
		
		Raises:
		  ConfigError: If unable to retrieve the configuration information
		    from the settings file.
		  
		"""
		self._connection = None
		try: 
			# Parse the configuration file
			config = configparser.ConfigParser(allow_no_value = False,
						interpolation = configparser.ExtendedInterpolation(),
						inline_comment_prefixes = ('#',';'))
			# Change the regex to allow spaces in the section name
			config.SECTCRE = regex.compile(r"\[ *(?P<header>[^]]+?) *\]")
			config.read(settingsFile)

			section = config.get('mysql', 'default_db')
			self.host = config.get(section, 'host')
			self.port = config.get(section, 'port')
			self.user = config.get(section, 'user')
			self.database = config.get(section, 'database')
			self.caCert = config.get(section, 'ca_certificate')
			self.certificate = config.get(section, 'certificate')
			self.privateKey = config.get(section, 'private_key')
		except configparser.Error as err:
			raise ConfigError('Problem reading database settings from '
				'the configuration file.') from err
	
	
	def connect(self):
		""" Connect to the database using a TLS connection.
		
		Raises:
		  mysql.connector.errors.Error: If the connection attempt fails.
		  
		"""
		self._connection = mysql.connector.connect(
			user = self.user, database = self.database,
			ssl_ca = self.caCert, ssl_verify_cert = False,
			ssl_cert = self.certificate, ssl_key = self.privateKey,
			host = self.host, port = self.port, autocommit = True)
		logging.info('Successfully connected to the database, %s, at %s:%s as user %s',
			   self.database, self.host, self.port, self.user)


	def close(self):
		""" Close the database connection. """
		if self._connection is not None:
			self._connection.close()
			logging.info('Closed any connection to the database')
	

# ----- Functions that wrap the database access
	
	def getEmployeeAtr(self, uid):
		""" Retrieve employee attributes from the database.
		
		This method retrieves the employee attributes from the database
		corresponding to the supplied user id and hash value.
		
		Args:
		  uid (string): The user id of the user whose attributes should
		    be fetched.
		  
		Returns:
		  tuple: A tuple containing the information about the user with the
		  specified uid.
		  
		  The attributes returned from the database are returned in the 
		  tuple in the order (uid, lastname, firstname, email)
		  
		Raises:
		  mysql.connector.errors.Error: If the select query fails.
		  
		"""
		statement = ('SELECT uid, lastname, firstname, email '
			'FROM users WHERE uid=%s')
		# Wrap in try finally to ensure the cursor is closed
		try:
			# Execute the statement and fetch the results
			cursor = self._connection.cursor(buffered = True)
			cursor.execute(statement, (uid,))
			
			resultTuple = cursor.fetchone()
		finally:
			cursor.close()
		return resultTuple
	
	
	def ensureAuthCall(self, uid, token):
		""" Verify that the user id and token match a value that is stored in
		the database. 
		
		This method checks the user id and token (user password hash) to ensure
		that they are indeed in the database. This method should be called at
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
			cursor = self._connection.cursor(buffered = True)
			cursor.execute(statement, data)
			resultTuple = cursor.fetchone()
			
			auth = 1 in resultTuple
		finally:
			cursor.close()
		return auth
	
	
	def updateExpiredCerts(self):
		""" Remove issued certificates from the mysql database whose expiry
		dates have passed. 
		
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		statement = ('UPDATE user_certs SET expired = TRUE '
			'WHERE exp_date < UTC_TIMESTAMP()')
		try:
			cursor = self._connection.cursor()
			cursor.execute(statement)
			logging.info('Successfully updated the issued certificates in the '
				'mysql database.')
		finally:
			cursor.close()
	
	
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
		statement = ('SELECT EXISTS(SELECT 1 FROM user_certs WHERE uid = %s '
			'AND revoked = FALSE AND expired = FALSE)')
		try:
			cursor = self._connection.cursor(buffered = True)
			cursor.execute(statement, (uid,))
			resultTuple = cursor.fetchone()
			
			exists = 1 in resultTuple
		finally:
			cursor.close()
		return exists
	
	
	def storeCert(self, uid, certificate, encKey):
		""" Store the provided certificate and encoded key pair for the
		specified user in the database. 
		
		Args:
		  uid (string): The employee's user id
		  certificate (imovies.certificate.Certificate): The certificate to store
		  encKey (string): The encrypted private key corresponding to the
		    provided certificate.
		
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		statement = ('INSERT INTO user_certs(uid, serial, exp_date, '
			'subject, certificate, private_key) VALUE (%s, %s, %s, %s, %s, %s)')
		data = (uid, certificate.serial, certificate.expiryDate, certificate.subject,
		  certificate.encoding, encKey)
		try:
			cursor = self._connection.cursor()
			cursor.execute(statement, data)
			logging.info('Successfully stored the issued certificate in the '
				'mysql database.')
		finally:
			cursor.close()
		
		
		