#!/usr/bin/env python

# origin format                     
# +--+------------------+
# |ID|IP sections       |
# +--+------------------+
# converted format
# ++-+-------+---------+-------+
# |ID|sec num|start-end|...    |
# ++-+-------+---------+-------+

import os
import sys
import string
import socket
import struct

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

# print a list of IP addresses based on the CIDR block specified
def printCIDR(c):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # "myString"[:-1] -> "myStrin" but "myString"[:0] -> ""
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        print bin2ip(baseIP)
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            print bin2ip(ipPrefix+dec2bin(i, (32-subnet)))

def cidr2range(c):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32:
        return (bin2ip(baseIP), bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        return (bin2ip(ipPrefix+dec2bin(0, (32-subnet))), bin2ip(ipPrefix+dec2bin(2**(32-subnet)-1, (32-subnet))))

def getID(str):
	s = str.split(' ')
	return s[0]

def getSecs(str):
	s = str.split(' ')
	return s[1]

def splitSec(str):
	s = str.split('-')
	return s

def str2uint(str):
	return socket.ntohl(struct.unpack('I', socket.inet_aton(str))[0])

def printUsage():
	print "Usage: ./pre_conv.py ip_file\n  e.g ./pre_conv.py id_ip_range\n"
    
def main():
	f = open(sys.argv[1])

	outfile = sys.argv[1] + "." + "maps"
	if (os.path.exists(outfile)):
		os.remove(outfile)
	f_out = open(outfile, 'w')

	for line in f:
		#id = string.atoi(getID(line)) - 1
		id = string.atoi(getID(line))
		secs = getSecs(line).split(',')
		for sec in secs:
			start = str2uint(splitSec(sec)[0]);
			end = str2uint(splitSec(sec)[1]);
			f_out.write(str(id) + ' ' + str(start) + ' ' + str(end) + '\n')

	f_out.close()
	f.close()

if __name__ == "__main__":
    main()

