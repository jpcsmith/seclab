import subprocess
import re

def getSerialID():
	certfile = '../CA/ca_cert.pem'
	
	cert_txt = subprocess.check_output(['openssl', 'x509', '-text', 
									 '-noout', '-in', certfile])
	
	