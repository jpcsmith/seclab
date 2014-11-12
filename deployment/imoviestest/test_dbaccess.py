import unittest
import imovies.errors
import mysql.connector
import imovies.dbaccess as dbaccess
from imovies.ca import Certificate
from tempfile import NamedTemporaryFile
import subprocess

class TestDBConnector(unittest.TestCase):
	""" Unit tests for the DBConnector class of module
	dbaccess. 
	
	Attributes:
	  cnx (connection.MySQLConnection): Root connection to the database
	  cursor (cursor.MySQLCursorBuffered): Buffered mysql cursor as root
	  db (imovies.dbaccess.DBConnector): Connector to the database being tested
	  
	"""
	
	@classmethod
	def setUpClass(cls):
		""" Create a connection to the database for modifying
		it during the tests. 
		
		"""
		cls.cnx = mysql.connector.connect(user = 'root', password = 'imoviestest',
										   autocommit = True)
		cls.cursor = cls.cnx.cursor(buffered = True)
	
	@classmethod
	def tearDownClass(cls):
		""" Tears down the connections """
		cls.cursor.close()
		cls.cnx.close()

	def setUp(self):
		""" Setup before each method invocation
		
		We reset the test_imovies database to a clone of the actual 
		starting database
		
		"""
		#self.cursor.callproc('imovies.clone_to_test')
		subprocess.check_call('mysql -u root -pimoviestest < ref/mysql_setup.sql', shell = True)
		self.cnx.database = 'imovies'
		
		self.db = dbaccess.DBConnector('imoviesca.cnf')
		self.db.connect()
		
	def tearDown(self):
		""" Tear down after each invocation """
		self.db.close()
	
	def test_getEmployeeAtr(self):
		""" Test the getEmployeeAtr method. """
		data = ('fu', 'Fuerst', 'Andreas', 'fu@imovies.ch')
		self.assertEqual(data, self.db.getEmployeeAtr('fu'));
		
		data = ('db', 'Basin', 'David', 'db@imovies.ch')
		self.assertEqual(data, self.db.getEmployeeAtr('db'));
		
	def test_ensureAuthCall(self):
		""" Test the ensureAuthCall method. """
		self.assertTrue(self.db.ensureAuthCall('fu', '6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7'))
		self.assertTrue(self.db.ensureAuthCall('db', '8d0547d4b27b689c3a3299635d859f7d50a2b805'))
		self.assertFalse(self.db.ensureAuthCall('ac', '7a347d4b27b689c3a3299635d859f7d50a2b805'))
	

	def test_updateExpiredCerts(self):
		""" Test the the updateExpiredCerts method. """
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject) VALUES"
			"('fu', 'A01', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 MONTH), 'testsub'), "
			"('db', 'A02', DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MONTH), 'testsub'), "
			"('ms', 'A03', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 MONTH), 'testsub'), "
			"('a3', 'A04', DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MONTH), 'testsub')")
		# Attempt to update those entries that expired
		self.db.updateExpiredCerts()
		
		# Verify corret update
		self.cursor.execute("SELECT uid, expired FROM user_certs")
		results = self.cursor.fetchall()
		self.assertTrue(('fu',0) in results and ('ms',0) in results
				  and ('db', 1) in results and ('a3', 1) in results)


	def test_hasIssued(self):
		""" Test the hasIssued function """
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES"
			"('fu', 'A01', UTC_TIMESTAMP(), 'testsub', FALSE, FALSE),"
			"('db', 'A02', UTC_TIMESTAMP(), 'testsub', FALSE, TRUE),"
			"('ms', 'A03', UTC_TIMESTAMP(), 'testsub', TRUE, FALSE),"
			"('a3', 'A04', UTC_TIMESTAMP(), 'testsub', TRUE, TRUE)")
		self.assertTrue(self.db.hasIssued('fu'))
		self.assertFalse(self.db.hasIssued('db'))
		self.assertFalse(self.db.hasIssued('ms'))
		self.assertFalse(self.db.hasIssued('a3'))
		
		
	def test_storeCert(self):
		""" Test the storeCert function """
		cert = ('-----BEGIN CERTIFICATE-----\n'
			'MIIEzTCCArWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBPMRAwDgYDVQQKDAdpTW92\n'
			'aWVzMRswGQYDVQQLDBJQS0kgSW5mcmFzdHJ1Y3R1cmUxHjAcBgNVBAMMFUNlcnRp\n'
			'ZmljYXRlIEF1dGhvcml0eTAeFw0xNDExMDgxODAxNTdaFw0xNTExMDgxODAxNTda\n'
			'MEcxEDAOBgNVBAoMB2lNb3ZpZXMxGzAZBgNVBAsMElRMUyBJbmZyYXN0cnVjdHVy\n'
			'ZTEWMBQGA1UEAwwNQmFja3VwIFNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEP\n'
			'ADCCAQoCggEBAMf4bGqdojZDPJO/vY5oEtU5rgvb9BDdbchLzndMsdSu4xrFzJgj\n'
			'8oHFUG3TZtmLCRkZsgzHnaXkmhPDY/kzWCKX6XBfgeChmz2xGqRNHCnKWckOMuzI\n'
			'KFCBZl4NsQJn+XNA3kp3cJFaWXbNIqRuMxo8JrRiPA7DOXKL3muEt1OVgOJHEYbc\n'
			'oPFQ2xfTgMc5sg8WLuD7Mrb4A/r56yWw0SxpvkEzxNQuQ3V/0eBhxzsCKZwl7VRV\n'
			'ZUZEzej57CcSgSPqhP1GeHIJ4PTIsKHTxHKkwoqbURWZFbIGNr71gKFVgV5W6iD0\n'
			'XfN/roLBHMGn6UJvsGiNPc2F6G5MCvp8bbMCAwEAAaOBuzCBuDAdBgNVHQ4EFgQU\n'
			'kpxK7ZN2aMcfuRMSuZ9gJN1c09swfwYDVR0jBHgwdoAUbBHJiwepZDeZCw7f8pI8\n'
			'glaic3KhU6RRME8xEDAOBgNVBAoMB2lNb3ZpZXMxGzAZBgNVBAsMElBLSSBJbmZy\n'
			'YXN0cnVjdHVyZTEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5ggkAwelb\n'
			'EUtYjiIwCQYDVR0TBAIwADALBgNVHQ8EBAMCA8gwDQYJKoZIhvcNAQELBQADggIB\n'
			'ACQcF+wtIrYclQDUnPd3v+5Cg99yMBfc0SZ6IJLJBwWpwBn9u9eOaia828TtAfj6\n'
			'x/y38xsUJTYo1wj0UpggoaucpZvwSAEloKA9rKMzsyWnPcKLpntfdPYaTEz42vUJ\n'
			'iPZ6Gt0PpkRwxqX0bQu+oJPUKKA9Jjd/W2ivVABPwStdiuSShmjxtCX81hIJaU8w\n'
			'LcXw/gjkum+AuMZq1+Y6JwIVO8/OdgzxK/JPksXZnEyPHgh531VXEfRb+nHtLCQE\n'
			'rPf/aoONFbUHzS3j1aZE/nRRpt+jAdB2I2y91JuenjpU9l2G+cJtpvsJQ9yRrolf\n'
			'+LnMLgHBYscugyoJxgm6Zm39HoyNUiXleIyWosZhYhRt6nuQNv5ElH0p2lECoYmo\n'
			'LS9IbhUcn5yXrmL783u4bG94DcGpAeIDLyat601GYgJh9gHkO2gSOK544ietUMhQ\n'
			'AgqBlJ/hkMkJBIrb8KOtmKG53SbAr2qyf9PPnLRYVGs3a+KHkOjWYS088UBshogD\n'
			'FI6LjUlpnorcnN3QPQeyD9H++XUekfdiYSok3qisAd+FssJBdn0QjKHzGYdtH43X\n'
			'Tfg8Ax0hSHO50R3HEP81hjbLANRYnYEIFxw5q4WWKZrmuj46DgMtx6Bh2B4KSqai\n'
			'uvWzN/87FU+xkFuORB6ZzUS8Bka2kq5a+Ihl27inlaDm\n'
			'-----END CERTIFICATE-----')
		certif = Certificate(cert)
		
		self.db.storeCert('fu', certif)
		self.assertTrue(self.db.hasIssued('fu'))

	def test_archiveCert(self):
		""" Test the archiveCert method """
		cert = ('-----BEGIN CERTIFICATE-----\n'
			'MIIEzTCCArWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBPMRAwDgYDVQQKDAdpTW92\n'
			'aWVzMRswGQYDVQQLDBJQS0kgSW5mcmFzdHJ1Y3R1cmUxHjAcBgNVBAMMFUNlcnRp\n'
			'ZmljYXRlIEF1dGhvcml0eTAeFw0xNDExMDgxODAxNTdaFw0xNTExMDgxODAxNTda\n'
			'MEcxEDAOBgNVBAoMB2lNb3ZpZXMxGzAZBgNVBAsMElRMUyBJbmZyYXN0cnVjdHVy\n'
			'ZTEWMBQGA1UEAwwNQmFja3VwIFNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEP\n'
			'ADCCAQoCggEBAMf4bGqdojZDPJO/vY5oEtU5rgvb9BDdbchLzndMsdSu4xrFzJgj\n'
			'8oHFUG3TZtmLCRkZsgzHnaXkmhPDY/kzWCKX6XBfgeChmz2xGqRNHCnKWckOMuzI\n'
			'KFCBZl4NsQJn+XNA3kp3cJFaWXbNIqRuMxo8JrRiPA7DOXKL3muEt1OVgOJHEYbc\n'
			'oPFQ2xfTgMc5sg8WLuD7Mrb4A/r56yWw0SxpvkEzxNQuQ3V/0eBhxzsCKZwl7VRV\n'
			'ZUZEzej57CcSgSPqhP1GeHIJ4PTIsKHTxHKkwoqbURWZFbIGNr71gKFVgV5W6iD0\n'
			'XfN/roLBHMGn6UJvsGiNPc2F6G5MCvp8bbMCAwEAAaOBuzCBuDAdBgNVHQ4EFgQU\n'
			'kpxK7ZN2aMcfuRMSuZ9gJN1c09swfwYDVR0jBHgwdoAUbBHJiwepZDeZCw7f8pI8\n'
			'glaic3KhU6RRME8xEDAOBgNVBAoMB2lNb3ZpZXMxGzAZBgNVBAsMElBLSSBJbmZy\n'
			'YXN0cnVjdHVyZTEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5ggkAwelb\n'
			'EUtYjiIwCQYDVR0TBAIwADALBgNVHQ8EBAMCA8gwDQYJKoZIhvcNAQELBQADggIB\n'
			'ACQcF+wtIrYclQDUnPd3v+5Cg99yMBfc0SZ6IJLJBwWpwBn9u9eOaia828TtAfj6\n'
			'x/y38xsUJTYo1wj0UpggoaucpZvwSAEloKA9rKMzsyWnPcKLpntfdPYaTEz42vUJ\n'
			'iPZ6Gt0PpkRwxqX0bQu+oJPUKKA9Jjd/W2ivVABPwStdiuSShmjxtCX81hIJaU8w\n'
			'LcXw/gjkum+AuMZq1+Y6JwIVO8/OdgzxK/JPksXZnEyPHgh531VXEfRb+nHtLCQE\n'
			'rPf/aoONFbUHzS3j1aZE/nRRpt+jAdB2I2y91JuenjpU9l2G+cJtpvsJQ9yRrolf\n'
			'+LnMLgHBYscugyoJxgm6Zm39HoyNUiXleIyWosZhYhRt6nuQNv5ElH0p2lECoYmo\n'
			'LS9IbhUcn5yXrmL783u4bG94DcGpAeIDLyat601GYgJh9gHkO2gSOK544ietUMhQ\n'
			'AgqBlJ/hkMkJBIrb8KOtmKG53SbAr2qyf9PPnLRYVGs3a+KHkOjWYS088UBshogD\n'
			'FI6LjUlpnorcnN3QPQeyD9H++XUekfdiYSok3qisAd+FssJBdn0QjKHzGYdtH43X\n'
			'Tfg8Ax0hSHO50R3HEP81hjbLANRYnYEIFxw5q4WWKZrmuj46DgMtx6Bh2B4KSqai\n'
			'uvWzN/87FU+xkFuORB6ZzUS8Bka2kq5a+Ihl27inlaDm\n'
			'-----END CERTIFICATE-----')
		certif = Certificate(cert)
		
		self.db.archiveCert(certif, 'encPrivKey', 'encIV', 'encSymKey', 'salt')
		self.cursor.execute('SELECT * FROM cert_archive')
		results = self.cursor.fetchone()
		self.assertTrue(cert in results)
		
	def test_getNIssued(self):
		""" Test the getNIssued inner method. """
		self.assertEqual(self.db.getNIssued(), 0)
		
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES"
			"('fu', 'A01', UTC_TIMESTAMP(), 'testsub', FALSE, FALSE),"
			"('db', 'A02', UTC_TIMESTAMP(), 'testsub', FALSE, TRUE),"
			"('ms', 'A03', UTC_TIMESTAMP(), 'testsub', TRUE, FALSE),"
			"('a3', 'A04', UTC_TIMESTAMP(), 'testsub', TRUE, TRUE)")
		self.assertEqual(self.db.getNIssued(), 4)
		
	def test_getNRevoked(self):
		""" Test the getNRevoked inner method """
		self.assertEqual(self.db.getNRevoked(), 0)
		
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES"
			"('fu', 'A01', UTC_TIMESTAMP(), 'testsub', FALSE, FALSE),"
			"('db', 'A02', UTC_TIMESTAMP(), 'testsub', FALSE, TRUE),"
			"('ms', 'A03', UTC_TIMESTAMP(), 'testsub', TRUE, FALSE),"
			"('a3', 'A04', UTC_TIMESTAMP(), 'testsub', TRUE, TRUE)")
		self.assertEqual(self.db.getNRevoked(), 2)
		
	def test_getIssuedSerial(self):
		""" Tests the function getIssuedSerial """
		self.assertIsNone(self.db.getIssuedSerial('fu'))
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES ('fu', 'A01', UTC_TIMESTAMP(), 'testsub', TRUE, FALSE)")
		self.assertIsNone(self.db.getIssuedSerial('fu'))
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES ('fu', 'A02', UTC_TIMESTAMP(), 'testsub', FALSE, TRUE)")
		self.assertIsNone(self.db.getIssuedSerial('fu'))
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES ('fu', 'A03', UTC_TIMESTAMP(), 'testsub', TRUE, TRUE)")
		self.assertIsNone(self.db.getIssuedSerial('fu'))
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES ('fu', 'A04', UTC_TIMESTAMP(), 'testsub', FALSE, FALSE)")
		self.assertEqual(self.db.getIssuedSerial('fu'), 'A04')
	
	
	def test_markRevoked(self):
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked) VALUES ('fu', 'A01', UTC_TIMESTAMP(), 'testsub', FALSE, FALSE)")
		self.db.markRevoked('A01')
		self.cursor.execute("SELECT revoked FROM user_certs WHERE serial = 'A01'")
		result = self.cursor.fetchone()
		self.assertTrue(1 in result)
	
	
	def test_updateLocalIndex(self):
		""" Test the updateLocalIndex function """
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"expired, revoked, rev_date) VALUES"
			"('fu', 'A01', '2015-11-11 17:30:00', 'testsub1', FALSE, FALSE, NULL),"
			"('db', 'A02', '2015-11-11 17:30:00', 'testsub2', FALSE, TRUE, '2014-10-11 17:30:00'),"
			"('ms', '0A03', '2014-10-11 17:30:00', 'testsub3', TRUE, FALSE, NULL),"
			"('a3', '0A04', '2014-10-11 17:30:00', 'testsub4', TRUE, TRUE, '2014-9-11 17:30:00')")
		
		referenceFile =  'imoviestest/support/refIndexFile.txt'

		with NamedTemporaryFile('w+t') as tempFile:
			self.db.updateLocalIndex(tempFile.name)
			process = subprocess.Popen(['diff', referenceFile, tempFile.name],
							  stdin = subprocess.PIPE, stdout = subprocess.PIPE,
							  stderr = subprocess.PIPE, universal_newlines = True)
			stdout, stderr = process.communicate()
			# Assert that nothing was printed to stdout, the files are equal
			self.assertEqual(stdout, '')
		
		
		
if __name__ == '__main__':
    unittest.main()