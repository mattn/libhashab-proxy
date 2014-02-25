#!/usr/bin/python
import cgi, cgitb
import ctypes
import binascii
import os

print "Content-type: text/plain\r\n\r\n",

q = cgi.parse_qs(os.environ.get("QUERY_STRING") or '')

lib_handle = ctypes.CDLL('/usr/lib64/libgpod/libhashab.so')
calcHashAB = lib_handle.calcHashAB
target = "f" * 57
calcHashAB(target,q['sha1'][0],q['uuid'][0],q['rndb'][0])
print binascii.hexlify(target)
