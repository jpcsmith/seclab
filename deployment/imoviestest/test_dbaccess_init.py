import unittest
import imovies.dbaccess as dbaccess
import mysql.connector
import imovies.errors

class TestDBCInitConnect(unittest.TestCase):
	""" Unit tests for the initialization and connection of the 
	DBConnector class of module dbaccess. 
	"""
	def setUp(self):
		self.db = None
	
	def tearDown(self):
		""" Tear down after each invocation """
		if self.db is not None:
			self.db.close()
	
	def test_init(self):
		""" Test the initialization of the class. """
		self.assertIsNotNone(dbaccess.DBConnector('imoviesca.cnf'))
		self.assertRaises(imovies.errors.ConfigError,
					lambda: dbaccess.DBConnector('does_not_exist.cnf'))
	
	def test_connectAndClose(self):
		""" Assert that the connect() and close() methods work. """
		self.db = dbaccess.DBConnector('imoviesca.cnf')
		self.db.connect()
		self.assertTrue(self.db._connection.is_connected())
		self.db.close()
		self.assertFalse(self.db._connection.is_connected())

if __name__ == '__main__':
    unittest.main()