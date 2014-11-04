import unittest
import imovies.ca as ca
import imovies.certparse as parse

class TestCertificateAuthority(unittest.TestCase):
	""" Unit tests for the CertificateAuthority class of module
	imovies.ca """
	
	def setUp(self):
		#self.db = dbaccess.DBConnector()
		#self.db.connect()
		pass
	
	def test_toText(self):
		parse.getSerialID()
	
	def tearDown(self):
		#self.db.close()
		pass
		
if __name__ == '__main__':
    unittest.main()