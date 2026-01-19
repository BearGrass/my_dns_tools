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

def main():
	f = open(sys.argv[1])

	outfile = sys.argv[1] + "." + "h"
	if (os.path.exists(outfile)):
		os.remove(outfile)
	f_out = open(outfile, 'w')

	for line in f:
		id = getID(line)
		name = getName(line)
		f_out.write('\t' + '{' + str(id) + ', ' + '"' + name.replace('\n', '') + '"' + '},' + '\n')

	f_out.close()
	f.close()

if __name__ == "__main__":
    main()


