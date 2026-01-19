#!/usr/bin/env python

import os
import sys
import string

def getID(str):
	s = str.split(' ')
	return s[0]

def getName(str):
	s = str.split(' ')
	return s[1]

def printUsage():
	print "Usage: ./id_name.py ip_name.txt\n  e.g ./id_name.py id_name\n"
    
def main():
	f = open(sys.argv[1])

	outfile = sys.argv[1] + "." + "maps"
	if (os.path.exists(outfile)):
		os.remove(outfile)
	f_out = open(outfile, 'w')

	for line in f:
		id_origin = getID(line)
		name_origin = getName(line)
		id = string.atoi(id_origin) - 1
		name = string.replace(name_origin, "_default", "")
		#print 'id: %d, name: %s' % (id, name)
		line = "%s%s \n"%(string.upper(name.replace("\n"," ")), str(id))
		#line = str(id) + ' ' + string.upper(name)
		f_out.write(line)

	f_out.close()
	f.close()

if __name__ == "__main__":
    main()

