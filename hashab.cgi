#!/usr/bin/python
import sys
import os
import cgi, cgitb
import ctypes
import binascii
import traceback

try:
  q = cgi.parse_qs(os.environ.get("QUERY_STRING") or '')
  lib_handle = ctypes.CDLL('/usr/lib64/libgpod/libhashab.so')
  calcHashAB = lib_handle.calcHashAB
  target = "0" * 57
  sha1 = binascii.unhexlify(q['sha1'][0])
  uuid = binascii.unhexlify(q['uuid'][0])
  rndb = binascii.unhexlify(q['rndb'][0])
  if len(sha1) != 20 or len(uuid) != 20 or len(rndb) != 23: raise Exception("Error")
  calcHashAB(target, sha1, uuid, rndb)
  print "HTTP/1.0 200 OK\r\n",
  print "Content-type: text/plain\r\n\r\n",
  print binascii.hexlify(target)
except:
  print "HTTP/1.0 400 Bad Request\r\n",
  print "Content-type: text/plain\r\n\r\n",
  print "Bad Request:\n" + traceback.format_exc(sys.exc_info()[2])
