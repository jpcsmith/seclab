import unittest
import imovies.dbaccess as dbaccess
import mysql.connector
import imovies.errors

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
		cls.cursor = cls.cnx.cursor()
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
		
		self.db = dbaccess.DBConnector('imoviesca_test.cnf')
		self.db.connect()
		
	def tearDown(self):
		""" Tear down after each invocation """
		self.db.close()
	
	def test_getEmployeeAtr(self):
		""" Test the getEmployeeAtr method. """
		data = (b'fu', b'Fuerst', b'Andreas', b'fu@imovies.ch')
		self.assertEqual(data, self.db.getEmployeeAtr('fu'));
		
		data = (b'db', b'Basin', b'David', b'db@imovies.ch')
		self.assertEqual(data, self.db.getEmployeeAtr('db'));
		
	def test_ensureAuthCall(self):
		""" Test the ensureAuthCall method. """
		self.assertTrue(self.db.ensureAuthCall('fu', '6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7'));
		self.assertTrue(self.db.ensureAuthCall('db', '8d0547d4b27b689c3a3299635d859f7d50a2b805'));
		self.assertFalse(self.db.ensureAuthCall('ac', '7a347d4b27b689c3a3299635d859f7d50a2b805'));
	
	def test_updateDatabase(self):
		""" The the updateDatabase method. """
		self.cursor.execute("INSERT INTO user_certs VALUES"
			"('fu', 'A01', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 MONTH)),"
			"('db', 'A02', DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MONTH)),"
			"('ms', 'A03', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 MONTH)),"
			"('a3', 'A04', DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MONTH))")
		# Attempt to delete those entries that expired
		self.db.updateDatabase()
		
		# Get the remaining entries
		self.cursor.execute("SELECT uid FROM user_certs")
		results = self.cursor.fetchall()
		self.assertTrue(('fu',) in results and ('ms',) in results)


	@unittest.skip('Not implemented')
	def test_hasIssued(self):
		pass
		
		
		"""('fu','Fuerst','Andreas','fu@imovies.ch','6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7'),('db','Basin','David','db@imovies.ch','8d0547d4b27b689c3a3299635d859f7d50a2b805'),('ms','Schlaepfer','Michael','ms@imovies.ch','4d7de8512bd584c3137bb80f453e61306b148875'),('a3','Anderson','Andres Alan','and@imovies.ch','6b97f534c330b5cc78d4cc23e01e48be3377105b');"""
	
	
	
	
		
if __name__ == '__main__':
    unittest.main()