import sys
import os
from xml.etree.ElementTree import ElementTree, Element
import xml.etree.ElementTree as ET

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from imovies.errors import InvalidCallError, IssuingError, TooManyIssuedError
from imovies.ca import CertificateAuthority
from mysql.connector.errors import Error as MySQLError

def main():
	# Create the common xml structure
	root = Element('result')
	
	uidElement = Element('uid')
	hashElement = Element('sha1')
	
	arguments = Element('arguments')
	arguments.append(uidElement)
	arguments.append(hashElement)
	
	root.append(arguments)
	
	try:
		# There should be 3 arguments total, the filename and 2 others
		if len(sys.argv) != 3:
			raise InvalidCallError('The number of arguments provided is not '
				'correct. usage: issue.py <uid> <pwd_hash>')
		else:
			uid = sys.argv[1]
			sha1Hash = sys.argv[2]
			
			uidElement.text = uid
			hashElement.text = sha1Hash
			
			certAuth = CertificateAuthority('../CA/imoviesca.cnf')
			
			pfx = certAuth.issueCert(uid, sha1Hash)
			#pfx = ('a4TwDedm+4zh7utWJ+bzrUhPWvzE0WcuZEwTrGAghwtZ/boVDYxzg71vmhl8EVej'
			#	'DPolsfJSQJX670mpwRYOwThDWVR3qZAtLBSo68WbtQ0RT2tQcD9qP9Outa+psIHo'
			#	'U9xlqCM1ClRVLJ22ku6PyBnCHZR6K+Ml2oCxkJDWka1FzKxordyp6lOhVGz+2zl0')
			
			# Create the arguments element and subelements
			pfxElement = Element('pkcs12')
			pfxElement.text = pfx
		
			root.append(pfxElement)
	except (InvalidCallError, IssuingError, MySQLError) as err:
		errorElement = Element('error', attrib = {'type':'IssuingError'})
		errorElement.text = str(err)
		root.append(errorElement)
	except TooManyIssuedError as err:
		errorElement = Element('error', attrib = {'type':'AlreadyIssued'})
		errorElement.text = str(err)
		root.append(errorElement)
	
	print(ET.tostring(root, encoding = 'unicode'))


if __name__ == "__main__": main()