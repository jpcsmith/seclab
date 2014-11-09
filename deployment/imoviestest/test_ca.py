import unittest
from imovies.ca import CertificateAuthority
from imovies.ca import Certificate
import logging
import subprocess
import imovies.errors
import mysql.connector
from tempfile import NamedTemporaryFile
import base64


class TestCertificateAuthority(unittest.TestCase):
	""" Unit tests for the CertificateAuthority class of module
	imovies.ca """
	
	@classmethod
	def setUpClass(cls):
		""" Create a connection to the database for modifying
		it during the tests. 
		
		"""
		cls.cnx = mysql.connector.connect(user = 'root', password = 'imoviestest',
										   autocommit = True)
		cls.cursor = cls.cnx.cursor(buffered = True)
		cls.cursor.execute("GRANT ALL ON imovies_test.* TO 'ca'@'%'")
		# Initialise the CA
		cls.ca = CertificateAuthority('imoviesca.cnf')
		
	@classmethod
	def tearDownClass(cls):
		""" Tears down the connections """
		cls.cursor.close()
		cls.cnx.close()
		cls.ca.db.close()

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
		
	def tearDown(self):
		pass


	def test_issueCert(self):
		""" Sanity check that the parts of the issueCert function hold together. """
		self.assertIsNotNone(self.ca.issueCert('fu', 
									 '6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7'))
	
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


	def test__toPKCS12(self):
		key = ('-----BEGIN PRIVATE KEY-----\n'
			'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPbQGHsT6aONxp6M\n'
			'jjEAZXoMuS22ZiJkVwPsuf2nK/aPy9bOHKU1TSNz/iBMJE/9OvAT5Lm0ZhPIRcSl\n'
			'ctZ+a9Y8d3HUgHs7rM1FWk+YWMsnTRUWr/Sq2PM+E4lWZH4tp0kStVzwNocjhQX7\n'
			'eh37bUTvw+9RsbfQrrZ/izO3ocefAgMBAAECgYEAqjdOCuPqyB9pEcOB9Q1+7rOD\n'
			'qqEWwzVMRaqnguYeDceSHyy62L1v27mNU5zvljLgyN4Panudwprmcv5fusopd5Y1\n'
			'F+tLyp55gP4U8l3bSq6YyLo5384Me5DCVOt3+BfTmxsZhpz752JedU5+MMJAbQAy\n'
			'Yr7AHrB849+KQIeq8VECQQD9tbjOsYSl+NxDFKHUhfd8Qmv8c2ndeeCclU0Kp+1/\n'
			'sO2mhI2ILG1T1DFuVtxNwz/IM19H5o0jJV7F4XLBlh6rAkEA+QpvoHWEsTTYU+EE\n'
			'JbAAb8+W1gzc3Lr9ZS8LM6MUbLFGKtvf/NQ2NXkfD6Ns0AmnoKnukD1vTI94E0zj\n'
			'DwPq3QJBALdQq0SlXVvy8WuCp9+AIK7m61GQLsj5PALHmc/+QAuIUl6D3iOrPh9Y\n'
			'7ZJ1Ll79mcNU4x53hjkD0nOWDy2zA1sCQHCPU/atRwUlAmWe/VXfX8Mpi15BwA2Q\n'
			'AnmaMrDrE48w7KrwaCOI8ttmXDCgR80boAUQ6T+OVODAs5/dj3644Y0CQCtpjYh9\n'
			'CpiEqs9gmTUZ0gnm3VthSPqKosB+eZRtUFjeGdWvgK57xxdKB6fk8RbilPayDpPD\n'
			'2wrJNhDYZKbcMX8=\n'
			'-----END PRIVATE KEY-----')
		certEnc = ('-----BEGIN CERTIFICATE-----\n'
			'MIIEzTCCArWgAwIBAgIBaDANBgkqhkiG9w0BAQsFADBPMRAwDgYDVQQKDAdpTW92\n'
			'aWVzMRswGQYDVQQLDBJQS0kgSW5mcmFzdHJ1Y3R1cmUxHjAcBgNVBAMMFUNlcnRp\n'
			'ZmljYXRlIEF1dGhvcml0eTAeFw0xNDExMDkxMzU4NDlaFw0xNTExMDkxMzU4NDla\n'
			'MIGIMRAwDgYDVQQKDAdpTW92aWVzMRYwFAYDVQQLDA1FbXBsb3llZSBCYXNlMQ4w\n'
			'DAYDVQQEDAVTbWl0aDEUMBIGA1UEKgwLSmVhbi1QaWVycmUxDzANBgNVBAMMBmpz\n'
			'bWl0aDElMCMGCSqGSIb3DQEJARYWanNtaXRoQHN0dWRlbnQuZXRoei5jaDCBnzAN\n'
			'BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA9tAYexPpo43GnoyOMQBlegy5LbZmImRX\n'
			'A+y5/acr9o/L1s4cpTVNI3P+IEwkT/068BPkubRmE8hFxKVy1n5r1jx3cdSAezus\n'
			'zUVaT5hYyydNFRav9KrY8z4TiVZkfi2nSRK1XPA2hyOFBft6HfttRO/D71Gxt9Cu\n'
			'tn+LM7ehx58CAwEAAaOB/TCB+jAdBgNVHQ4EFgQU3HTF2iGQ/iT9o/4DCdr3WjP9\n'
			'KcUwfwYDVR0jBHgwdoAUbBHJiwepZDeZCw7f8pI8glaic3KhU6RRME8xEDAOBgNV\n'
			'BAoMB2lNb3ZpZXMxGzAZBgNVBAsMElBLSSBJbmZyYXN0cnVjdHVyZTEeMBwGA1UE\n'
			'AwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5ggkAwelbEUtYjiIwCQYDVR0TBAIwADAL\n'
			'BgNVHQ8EBAMCA8gwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMCEGA1Ud\n'
			'EQQaMBiBFmpzbWl0aEBzdHVkZW50LmV0aHouY2gwDQYJKoZIhvcNAQELBQADggIB\n'
			'AD/JNoUFn/vjKy9x6UpjPnkBlXslGF5UJQBNjIJ+blApJs1cRpoX0sV7YcSf9iNz\n'
			'n3oX/BdHZ78Hi+zgtgFZanYbbwpZhjT6+2fL2RyCamYeQmY7N5NHpv7Pf0ax695X\n'
			'D3hhD0jtyAH6cIw54IRXAGBH+CeiYk38W+U/xJGGFh9wR+YYbYkPrbueJhrB1Fii\n'
			'SSpvvMl8MwxdtP1X995GZlJVSoJ+xlnbMJgkDJKA2O7bAV4HMN5AHn+SBO9/Ow3n\n'
			'9i7WALJbFrlbaGAyMrnKIfS6kXIbPWl/2qz1PBmUAWhGN+56Pg+evIZT9+y+xzow\n'
			'7LMJs3VPjoEH8rapKsq7F03EuZbY+4meDnWQrCitNXUOfXaapxhncjtJDTxJWSth\n'
			'NidSRJir3k8Lx7QY9zm6MVG0td3k2f5w9asgTMb7g57PqL49GqBPl4pv3LAuj8QD\n'
			'b+s+TjfGejgkrmh6qIhoBnkKPUYatxax4I0bYHNaM1zUEeocXk+8uB8FsBE5SRgp\n'
			'dsa/PJqsPxgcgzBOMf+RS1YzwXfctaPZgnezORRUUG8n6GtdRtUyQLx8ZxRfcAIj\n'
			'lI1WuvRAxww+Lj0Ms64gZisHKPBa0piDNT5O3zsYI2rAliNKE+fTM6RjahpzhvQ7\n'
			'UFPGKnrvpVZSZgqFjBnPI28uce8YoJBvMHyuBDeHu9As\n'
			'-----END CERTIFICATE-----')
		pfx = self.ca._toPKCS12('example', Certificate(certEnc), key)
		
		
		# Check that the pfx byte array creates a pareable object
		with open('temp.pfx', 'w+b') as temp:
			temp.write(pfx)
			temp.flush()
			process = subprocess.Popen(['openssl', 'pkcs12', '-in', temp.name,
							   '-passin', 'pass:', '-nodes'], 
							stdin = subprocess.PIPE, stdout = subprocess.DEVNULL,
							stderr = subprocess.DEVNULL)
			process.communicate()
			self.assertEqual(process.returncode, 0)		


if __name__ == '__main__':
    unittest.main()