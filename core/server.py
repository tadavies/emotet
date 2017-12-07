from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, SHA256
from google.protobuf.json_format import MessageToJson
from datetime import datetime
from collections import namedtuple
import socket
import json
import binascii
import struct
import zlib
import emotet_pb2
import http.client
import base64


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def decodeVarint(stream):
    """Lazily decodes a stream of VARINTs to Python integers."""
    offset = 1
    value = 0
    base = 1
    for raw_byte in stream:
        val_byte = ord(raw_byte)
        value += (val_byte & 0x7f) * base
        if (val_byte & 0x80):
            # The MSB was set; increase the base and iterate again, continuing
            # to calculate the value.
            base *= 128
            offset += 1
        else:
            # The MSB was not set; this was the last byte in the value.
            return value, offset

class server(object):
	def __init__(self):
		self.rsaKey = None
		self.sessionKey = None

	def loadKey(self, keyPath):
		f = open(keyPath, "rb")
		rawKey = f.read()
		f.close()
		self.rsaKey = RSA.importKey(rawKey, passphrase="test")

	def decrypt(self, buf):
		ret = None
		if len(buf) < 116:
			print "Decrypt - Not enough Data"
			return None
		sessionKeyData = buf[0:96]
		sha1 = buf[96:116]
		data = buf[116:]
		#Get session key
		rsa = PKCS1_OAEP.new(self.rsaKey)
		self.sessionKey = rsa.decrypt(sessionKeyData)
		#AES Decrypt
		cipher_aes = AES.new(self.sessionKey, AES.MODE_CBC, '\x00' *16)
		data = cipher_aes.decrypt(data)
		#remove padding
		data = unpad(data)
		#Check SHA
		h = SHA.new()
		h.update(data)
		if sha1 == h.digest():
			ret = data
		return ret

	def encrypt(self, data):
		#data = zlib.compress(data)
		digest = SHA.new()
		digest.update(data)
		signer = PKCS1_v1_5.new(self.rsaKey)
		a = signer.sign(digest)
		cipher = AES.new(self.sessionKey, AES.MODE_CBC, '\x00' * 16)
		data = pad(data)
		enc = cipher.encrypt(data)
		return a + digest.digest() + enc

	def parse(self ,data):
		decryptedData = self.decrypt(data)
		if decryptedData == None:
			print "Decrypt Error"
			return None
		fo = open(datetime.now().strftime('%Y%m%d_%H%M%S') + "clientReq.bin", "wb")
		fo.write(decryptedData)
		fo.close()
		#Get Outer PROTO
		outer = emotet_pb2.RegistrationRequest()
		try:
			outer.ParseFromString(decryptedData)
		except Exception as e:
			print e 
			return
		if outer.command == 16:
			#Get inner PROTO
			innerData = zlib.decompress(outer.data)
			inner = emotet_pb2.RegistrationRequestBody()
			inner.ParseFromString(innerData)
			print MessageToJson(inner)
			if inner.moduleList == "":
				#Return modules
				fo = open("testData/decryptedModules.bin")
				ret = fo.read()
				fo.close()
				return self.encrypt(ret)
			else:
				#Return blank command
				print len(inner.moduleList)
				fo = open("testData/decryptedBlank.bin")
				ret = fo.read()
				fo.close()
				return self.encrypt(ret)
		else:
			print MessageToJson(outer)

