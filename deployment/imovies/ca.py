from .dbaccess import DBConnector

class CertificateAuthority:
	
	__init__(self):
		self._connector = DBConnector()
	
	issueCert(self, uid, pHash):
		try:
			# Do the call authentication check
			if (!self._connector.ensureAuthCall(uid, pHash))
				raise 
			
		# Check if the user already has a certificate issued
		
		
		
	
		