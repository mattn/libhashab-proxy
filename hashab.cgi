#!/usr/bin/python
import cgi, cgitb
import ctypes
import binascii
import os

print "Content-type: text/html\n\n"

q = cgi.parse_qs(os.environ["QUERY_STRING"])

lib_handle = ctypes.CDLL('./libhashab64.so')
calcHashAB = lib_handle.calcHashAB
target = "f" * 57
calcHashAB(target,q['sha1'][0],q['uuid'][0],q['rndb'][0])
print binascii.hexlify(target)
