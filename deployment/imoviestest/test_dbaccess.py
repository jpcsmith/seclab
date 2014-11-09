import unittest
import imovies.dbaccess as dbaccess
import mysql.connector
import imovies.errors
from imovies.ca import Certificate

class TestDBConnector(unittest.TestCase):
	""" Unit tests for the DBConnector class of module
	dbaccess. """
	
	@classmethod
	def setUpClass(cls):
		""" Create a connection to the database for modifying
		it during the tests. 
		
		"""
		cls.cnx = mysql.connector.connect(user = 'root', password = 'imoviestest',
										   autocommit = True)
		cls.cursor = cls.cnx.cursor(buffered = True)
		cls.cursor.execute("GRANT ALL ON imovies_test.* TO 'ca'@'%'")
	
	@classmethod
	def tearDownClass(cls):
		""" Tears down the connections """
		cls.cursor.close()
		cls.cnx.close()

	def setUp(self):
		""" Setup before each method invocation
		
		We reset the imovies_test database to a clone of the actual 
		starting database
		
		"""
		self.cursor.execute('DROP DATABASE IF EXISTS imovies_test')
		self.cursor.execute('CREATE DATABASE imovies_test')
		self.cursor.execute('USE imovies_test')
		self.cursor.execute('CREATE TABLE users LIKE imovies.users')
		self.cursor.execute('CREATE TABLE user_certs LIKE imovies.user_certs')
		self.cursor.execute('INSERT INTO users SELECT * FROM imovies.users')
		self.cursor.execute('INSERT INTO user_certs SELECT * FROM imovies.user_certs')
		
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
		self.cursor.execute("INSERT INTO user_certs(uid, serial, exp_date, subject, "
			"certificate, private_key) VALUES"
			"('fu', 'A01', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 MONTH), "
				"'testsub', 'testcert', 'testkey'),"
			"('db', 'A02', DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MONTH), "
				"'testsub', 'testcert', 'testkey'),"
			"('ms', 'A03', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 MONTH), "
				"'testsub', 'testcert', 'testkey'),"
			"('a3', 'A04', DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MONTH), "
				"'testsub', 'testcert', 'testkey')")
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
			"certificate, private_key, expired, revoked) VALUES"
			"('fu', 'A01', UTC_TIMESTAMP(), 'testsub', 'testcert', 'testkey', FALSE, FALSE),"
			"('db', 'A02', UTC_TIMESTAMP(), 'testsub', 'testcert', 'testkey', FALSE, TRUE),"
			"('ms', 'A03', UTC_TIMESTAMP(), 'testsub', 'testcert', 'testkey', TRUE, FALSE),"
			"('a3', 'A04', UTC_TIMESTAMP(), 'testsub', 'testcert', 'testkey', TRUE, TRUE)")
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
		
		self.db.storeCert('fu', certif, 'testKey')
		self.assertTrue(self.db.hasIssued('fu'))
		
		self.cursor.execute("SELECT certificate FROM user_certs WHERE "
			"serial = %s", (certif.serial, ))
		self.assertEqual(self.cursor.fetchone()[0], cert)
		
	
if __name__ == '__main__':
    unittest.main()