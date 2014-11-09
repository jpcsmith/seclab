import unittest
from imovies.ca import CertificateAuthority
from imovies.ca import Certificate
import logging
import subprocess
import imovies.errors

class TestCertificateAuthority(unittest.TestCase):
	""" Unit tests for the CertificateAuthority class of module
	imovies.ca """
	
	@classmethod
	def setUpClass(cls):
		cls.ca = CertificateAuthority('imoviescaV2.cnf')
		
	@classmethod
	def tearDownClass(cls):
		cls.ca.db.close()
	
	@unittest.skip('Cant test more than the tested dbaccess method.')
	def test__updatedb(self):
		""" Tests the internal function _updatedb of the CertificateAuthority
		class """
		pass
	
	def test__req(self):
		""" Test the internal function _req of the CertificateAuthority class. """
		
		# Attempt to generate a private key and CSR
		privateKey, csr = self.ca._req('jsmith', 'Smith', 'Jean-Pierre', 'jsmith@student.ethz.ch')
		
		# Test the private key
		process = subprocess.Popen(['openssl', 'pkey', '-text', '-noout'], 
							 stdin = subprocess.PIPE, stdout = subprocess.DEVNULL, 
							 stderr = subprocess.DEVNULL, universal_newlines = True);
		process.communicate(privateKey)
		# Assert that there were no error messages
		self.assertEqual(process.returncode, 0)
		
		# Test the certificate signing request
		process = subprocess.Popen(['openssl', 'req', '-noout', '-subject'], 
							 stdin = subprocess.PIPE, stdout = subprocess.PIPE, 
							 stderr = subprocess.DEVNULL, universal_newlines = True);
		stdout, stderr = process.communicate(csr)
		self.assertEqual(process.returncode, 0)
		self.assertEqual(stdout.rstrip(), 
				   'subject=/O=iMovies/OU=Employee Base/SN=Smith/GN=Jean-Pierre'
				   '/CN=jsmith/emailAddress=jsmith@student.ethz.ch')
	
	def test__sign(self):
		""" Test the CertificateAuthority inner function _sign. """
		""" A csr corresponding the the subject:
			subject=/O="iMovies"/OU="Employee Base"/SN="Smith"/GN="Jean-Pierre"
				   /CN="jsmith"/emailAddress="jsmith@student.ethz.ch" 
		"""
		csr = ('-----BEGIN CERTIFICATE REQUEST-----\n'
			'MIIByTCCATICAQAwgYgxEDAOBgNVBAoMB2lNb3ZpZXMxFjAUBgNVBAsMDUVtcGxv\n'
			'eWVlIEJhc2UxDjAMBgNVBAQMBVNtaXRoMRQwEgYDVQQqDAtKZWFuLVBpZXJyZTEP\n'
			'MA0GA1UEAwwGanNtaXRoMSUwIwYJKoZIhvcNAQkBFhZqc21pdGhAc3R1ZGVudC5l\n'
			'dGh6LmNoMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9EtdkhPTUtxqki5CO\n'
			'1KuAt6847a5fupZ/r3TtCKdLLQOsNt/1YUBruJophu9N9TTS/oQ5fram3NY2vsad\n'
			'i+VXzIZJYKuNBuEJfRRBvN9thaDZrxfpQ8uUQ5xKQsqi62kgjFtJfE2AadKUhh/t\n'
			'oShuSxKBCTvve1icdJt3avjSxQIDAQABoAAwDQYJKoZIhvcNAQELBQADgYEAgkpO\n'
			'iC76VFo01bkQWGcmjwANMHGUFNBqh8+A8hOQQ3QCppiAukiWYFmPCGm1WuzFoFTz\n'
			'oA8KwK51L6qKHPcwDe2GKQvLgmiS1Zt6HXZhLPxT7IQqyFpAilAWmhlMLFPYB+IL\n'
			'U1G30WGdc0DZH2Yp+H6BIjPX6apPcm+C4XsHe5A=\n'
			'-----END CERTIFICATE REQUEST-----')
		
		# Test using a valid CSR
		cert = self.ca._sign(csr)
		self.assertEqual(cert.subject, '/O=iMovies/OU=Employee Base/SN=Smith'
				   '/GN=Jean-Pierre/CN=jsmith/emailAddress=jsmith@student.ethz.ch')
		
		# Test using an invalid CSR
		badcsr = '-----BEGIN CERTIFICATE REQUEST-----\nNot a valid csr\n-----END CERTIFICATE REQUEST-----'
		self.assertRaises(imovies.errors.IssuingError, 
					lambda: self.ca._sign(badcsr))
	
	def test_Certificate(self):
		""" Tests the Certificate class of the imovies.ca module """
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
		# Test using valid certificate
		self.assertEqual(Certificate(cert).subject,
				   '/O=iMovies/OU=TLS Infrastructure/CN=Backup Server')
		# Test using invalid certificate
		self.assertRaises(imovies.errors.CertificateParsingError,
			lambda: Certificate('-----BEGIN CERTIFICATE-----\n'
			'Not valid\n-----END CERTIFICATE-----'))

if __name__ == '__main__':
    unittest.main()