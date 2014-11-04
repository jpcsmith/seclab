import unittest
import imovies.dbaccess as dbaccess

class TestDBConnector(unittest.TestCase):
	""" Unit tests for the DBConnector class of module
	dbaccess. """
	
	def setUp(self):
		self.db = dbaccess.DBConnector()
		self.db.connect()
	
	def test_connect_close(self):
		""" Assert that the connect() and close() methods work. """
		self.assertTrue(self.db._connection.is_connected())
		self.db.close()
		self.assertFalse(self.db._connection.is_connected())
		self.db.connect()
		self.assertTrue(self.db._connection.is_connected())
	
	def test_getEmployeeAtr(self):
		""" Assert that the get employee attribute method works. """
		dbVals = { 'uid':b'fu', 'lname':b'Fuerst', 'fname':b'Andreas', 
			'email':b'fu@imovies.ch' }
		result = self.db.getEmployeeAtr('fu')
		self.assertEqual(dbVals, result)
		
		dbVals = { 'uid':b'db', 'lname':b'Basin', 'fname':b'David', 
			'email':b'db@imovies.ch' }
		result = self.db.getEmployeeAtr('db')
		self.assertEqual(dbVals, result)
	
	def test_ensureAuthCall(self):
		""" Assert that the ensureAuthCall method works. """
		result = self.db.ensureAuthCall('fu', '6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7')
		self.assertTrue(result)
		
		result = self.db.ensureAuthCall('db', '6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7')
		self.assertFalse(result)
	
	def test_hasIussed(self):#TODO Check for one that has issued
		""" Asserts that the hasIssued method works. """
		self.assertFalse(self.db.hasIssued('fu'))
	
	def tearDown(self):
		self.db.close()
		
if __name__ == '__main__':
    unittest.main()