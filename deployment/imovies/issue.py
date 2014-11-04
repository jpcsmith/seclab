

import sys, getopt

nARGS = 2

class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg
	def __str__(self):
		return "<exception>\n\t<msg>" + self.msg + " | usage: issue.py <user id> <pwd hash> </msg>\n</exception>"

def main(argv = None):
	if argv is None:
		argv = sys.argv[1:]
	
	if len(argv) != nARGS:
		print(Usage("Missing arguments"))
		return 2
	
	uid = argv[0]
	pHash = argv[1]

if __name__ == "__main__":
	sys.exit(main())
