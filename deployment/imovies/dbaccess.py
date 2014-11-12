""" Handles database connection and access for the Certificate Authority.

This module primarily provides the DBConnector class which is used to
connect to and transact with the database. 
  
"""

import io
import re as regex
from .errors import ConfigError
from .certificate import Certificate
import configparser, mysql.connector, logging
from datetime import tzinfo, datetime, timezone, timedelta

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
			ssl_ca = self.caCert, ssl_verify_cert = True,
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
			cursor = None
			cursor = self._connection.cursor(buffered = True)
			cursor.execute(statement, (uid,))
			
			resultTuple = cursor.fetchone()
		finally:
			if cursor is not None:
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
		data = (uid, token, False)
		try:
			cursor = None
			cursor = self._connection.cursor(buffered = True)
			oUID, oToken, isValid = cursor.callproc('check_login', data)
			auth = (isValid == 1)
		finally:
			if cursor is not None:
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
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement)
			logging.info('Successfully updated the issued certificates in the '
				'mysql database.')
		finally:
			if cursor is not None:
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
			cursor = None
			cursor = self._connection.cursor(buffered = True)
			cursor.execute(statement, (uid,))
			resultTuple = cursor.fetchone()
			
			exists = 1 in resultTuple
		finally:
			if cursor is not None:
				cursor.close()
		return exists
	
	
	def storeCert(self, uid, certificate):
		""" Store the provided certificate as issued for the user.
		
		Args:
		  uid (string): The employee's user id
		  certificate (imovies.certificate.Certificate): The certificate to store
		
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		statement = ('INSERT INTO user_certs(uid, serial, exp_date, subject) '
			'VALUE (%s, %s, %s, %s)')
		data = (uid, certificate.serial, certificate.expiryDate, certificate.subject)
		try:
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement, data)
			logging.info('Successfully stored the issued details in the '
				'mysql database.')
		finally:
			if cursor is not None:
				cursor.close()
		
	def archiveCert(self, certificate, encPrivKey, encIV, encSymKey, salt):
		""" Store the certificate and private key in the archive.
		
		Args:
		   certificate (imovies.certificate.Certificate): The certificate to
		     store.
		   encPrivKey (string): Base64 encoded private key encrypted.
		   encIV (string): Base64 encoded initialization vector, encrypted
		     under the archive public key.
		   encSymKey (string): Base64 encoded symmetric key encrypted under
		     the archive public key.
		   salt (string): Hex string salt value used in the sym encryption.
		   
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		  
		"""
		statement = ('INSERT INTO cert_archive(serial, certificate, '
			'encrypted_priv_key, salt, encrypted_sym_key, encrypted_iv)'
			'VALUE (%s, %s, %s, %s, %s, %s)')
		data = (certificate.serial, certificate.encoding, encPrivKey,
		  salt, encSymKey, encIV)
		try:
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement, data)
			logging.info('Successfully stored the certificate in the '
				'mysql archive table.')
		finally:
			if cursor is not None:
				cursor.close()
	
	
	def getNIssued(self):
		""" Gets the number of certificates issued as per the user_certs 
		table.
		
		Returns:
		  int: the number of certificates issued, including expired and
		  revoked certificates.
		  
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		statement = 'SELECT COUNT(*) FROM user_certs'
		try:
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement)
			resultTuple = cursor.fetchone()
			return resultTuple[0]
		finally:
			if cursor is not None:
				cursor.close()
	
	
	def getNRevoked(self):
		""" Gets the number of employee certificates revoked as per the 
		user_certs table.
		
		Returns:
		  int: the number of employee certificates revoked
		  
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		statement = ('SELECT COUNT(*) FROM user_certs '
			'WHERE revoked = TRUE')
		try:
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement)
			resultTuple = cursor.fetchone()
			return resultTuple[0]
		finally:
			if cursor is not None:
				cursor.close()
			
	def isAdmin(self, serial):
		""" Checks that the user that the certificate was issued to is
		an admin.
		
		Args:
		  The serial number of the admin's certificate
		
		Returns:
		  bool: True if they are an admin, False otherwise.
		  
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		  
		"""
		data = (serial, False)
		try:
			cursor = None
			cursor = self._connection.cursor()
			oSerial, isAdmin = cursor.callproc('imovies.is_admin', data)
		finally:
			if cursor is not None:
				cursor.close()
		return True if isAdmin == 1 else False
		
		
		
	def getIssuedSerial(self, uid):
		""" Gets the serial number of the certificate issued to a user
		that is neither revoked nor expired.
		
		Args:
		  uid (string): The user id of the user whose cert-serial we wish
		  to fetch.
		
		Returns:
		  string or None: A serial corresponding to a certificate issued to 
		  user with id uid that has neither been revoked or expired or None 
		  if no such serials exist.
		
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		
		"""
		statement = ('SELECT serial FROM user_certs WHERE '
			'uid = %s AND revoked = FALSE AND expired = FALSE')
		data = (uid, )
		try:
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement, data)
			result = cursor.fetchone()
			if result is not None:
				result = result[0]
			return result
		finally:
			if cursor is not None:
				cursor.close()

	def markRevoked(self, serial):
		""" Marks a certificate in the database as being revoked and sets
		the time of its revocation.
		
		Args:
		  serial (string): The serial of the certificate to revoke.
		  
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		  OSError: If the file cannot be written to

		"""
		statement = ('UPDATE user_certs SET revoked = TRUE, rev_date = UTC_TIMESTAMP() '
			'WHERE serial = %s')
		data = (serial, )
		try:
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement, data)
		finally:
			if cursor is not None:
				cursor.close()
				
	def updateLocalIndex(self, indexFile):
		""" Updates the local text database to match the remote mysql database by 
		rewriting it.
		
		Args:
		  indexFile (string): The filename of the index file to write the 
		    information to.
		
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		  OSError: If the file cannot be read
		
		Notes:
		  The index file consists of zero or more lines, each containing the 
		  following fields separated by tab characters:
			- Certificate status flag (V=valid, R=revoked, E=expired). (E is not 
				used I believe)
			- Certificate expiration date in YYMMDDHHMMSSZ format.
			- Certificate revocation date in YYMMDDHHMMSSZ[,reason] format. 
				Empty if not revoked.
			- Certificate serial number in hex.
			- Certificate filename or literal string ‘unknown’.
			- Certificate distinguished name
			
		"""
		statement = 'SELECT * FROM user_certs'
		try:
			cursor = None
			cursor = self._connection.cursor(dictionary = True)
			cursor.execute(statement)
			
			with open(indexFile, 'w', encoding="utf-8") as index:
				for rowDict in cursor:
					line = '{0}\t{1}\t{2}\t{3}\t{4}\t{5}\n'.format(
						'R' if rowDict['revoked'] == 1 else 'V',
						rowDict['exp_date'].strftime('%y%m%d%H%M%SZ'),
						'' if rowDict['rev_date'] is None else 
							rowDict['rev_date'].strftime('%y%m%d%H%M%SZ'),
						rowDict['serial'] if len(rowDict['serial']) % 2 == 0 else '0' + rowDict['serial'],
						'unknown',
						rowDict['subject'])
					index.write(line)
		finally:
			if cursor is not None:
				cursor.close()


	def storeCRL(self, crl):
		""" Pushes a CRL to the database 
		
		Args:
		  crl (string): The pem encoded CRL to store
		  
		Raises:
		  mysql.connector.errors.Error: If the database query fails.
		  
		"""
		statement = ('INSERT INTO crl_list(gen_date, crl) '
			'VALUE (UTC_TIMESTAMP(), %s)')
		data = (crl, )
		try:
			cursor = None
			cursor = self._connection.cursor()
			cursor.execute(statement, data)
		finally:
			if cursor is not None:
				cursor.close()