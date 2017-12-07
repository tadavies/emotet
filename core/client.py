from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, SHA256
from datetime import datetime
import socket
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

class client(object):
	def __init__(self, config=None):
		self.rsaKey = None
		self.conf = config
		self.aesKey = '0123456789abcdef'
		if self.conf != None:
			self.rsaKey = RSA.importKey(self.conf['PublicKey'])

	def decrypt(self, data):
		if len(data) < 116:
			return None
		signature = data[0:96]
		sha1 = data[96:116]
		payload = data[116:]
		#AES Decrypt
		cipher_aes = AES.new(self.aesKey, AES.MODE_CBC, '\x00' *16)
		data = cipher_aes.decrypt(payload)
		#Remove padding
		data = unpad(data)
		#Verify check
		digest = SHA.new()
		digest.update(data)
		if digest.digest() != sha1:
			return None
		return data

	def encrypt(self, data):
		#Check RSA key is loaded
		#if self.rsaKey == None:
			#self.rsaKey = RSA.importKey(self.conf['PublicKey'])

		#Export session key
		rsa = PKCS1_OAEP.new(self.rsaKey)
		session = rsa.encrypt(self.aesKey)
		#SHA1 hash data
		h = SHA.new()
		h.update(data)
		sha = h.digest()
		#AES encrypt data
		cipher = AES.new(self.aesKey, AES.MODE_CBC, '\x00' * 16)
		data = pad(data)
		enc = cipher.encrypt(data)
		return session + sha + enc

	def sendMsg(self, server, data):
		conn = None
		tu = server.split(':')
		if tu[1] == 443:
			conn = http.client.HTTPSConnection(server, timeout=10)
		else:
			conn = http.client.HTTPConnection(server, timeout=10)
		
		try:
			conn.connect()
		except (socket.error) as e:
			print("Exception on ", server, e)
			return

		conn.putrequest("POST", "/", skip_accept_encoding=True, skip_host=True)
		conn.putheader("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)")
		conn.putheader("Host", server)
		conn.putheader("Content-Length",str(len(data)))
		conn.putheader("Connection", "Keep-Alive")
		conn.putheader("Cache-Control", "no-cache")
		conn.endheaders(data)
		try:
			resp = conn.getresponse()
			beaconresp = resp.read()
			if len(beaconresp) > 0:
				return beaconresp
		except (http.client.HTTPException, socket.error) as e:
			print("Exception on ", server, e)
		return None

	def getReqMessage(self):
		#Build inner message
		message = emotet_pb2.RegistrationRequestBody()
		message.command = 1
		message.botId  = self.conf['BotId']
		message.osVersion = self.conf['OsVersion']
		message.crc32  = self.conf['VersionCRC']
		message.procList = self.conf['ProcList']
		message.unknown = self.conf['Unknown']
		message.moduleList = ""
		for mod in self.conf['ModuleList']:
			message.moduleList += struct.pack("I", mod)
		#Build outer message
		req = emotet_pb2.RegistrationRequest()
		req.command = 16
		req.data = zlib.compress(message.SerializeToString())
		return self.encrypt(req.SerializeToString())

	def getSpamMessage(self):
		#Build inner message
		message = emotet_pb2.SpamRequestBody()
		message.botId  = self.conf['BotId']
		message.magicId = 31458394
		message.unk1 = ""
		message.unk2 = ""
		#Build outer message
		req = emotet_pb2.RegistrationRequest()
		req.command = 0x18
		req.data = zlib.compress(message.SerializeToString())
		return self.encrypt(req.SerializeToString())

	def responseHandler(self, data):
		#Decrypt
		self.logFile("raw", data)
		data = self.decrypt(data)
		if data == None:
			print "{0} Decrypt failed".format(self.time)
			return None
		self.logFile("decrypted", data)
		#Uncompress
		unComp = None
		unCompLen = struct.unpack("I", data[:4])[0]
		if unCompLen == 0:
			print "{0} No data to uncompress".format(self.time)
			return None
		try:
			unComp = zlib.decompress(data[4:])
		except Exception as e:
			print e
		if unComp == None:
			print "{0} Decompressing data failed".format(self.time)
			return None
		self.logFile("inner", unComp)
		#Convert to protobuf
		res = emotet_pb2.RegistrationResponse()
		try:
			res.ParseFromString(unComp)
		except Exception as e:
			print "{0} Converting to protobuf failed: {1}".format(self.time, e)
			return None
	#print MessageToJson(res)
		return res

	def loaderHandler(self, data):
		crc = binascii.crc32(data) & 0xffffffff
		self.logFile("loader", data)
		print "{0} New loader CRC32:{1}".format(self.time, crc)
	
	def moduleHandler(self, data):
		offset = 0
		while offset < len(data):
			v = decodeVarint(data[offset:])
			start = offset + v[1]
			end = offset + v[1] + v[0]
			offset += (v[1] + v[0])
			module = emotet_pb2.Module()
			module.ParseFromString(data[start:end])
			self.logFile(str(module.type), module.data)
			print "{0} Got module with type: {1}".format(self.time, module.type)

	def start(self):
		request = self.getReqMessage()
		for server in self.conf["C2List"]:
			self.time = datetime.now().strftime('%Y%m%d_%H%M%S')
			print "{0} Connecting to: {1}".format(self.time, server)
			response = self.sendMsg(server, request)
			if response:
				print "{0} Response len: {1}".format(self.time, len(response))
				res = self.responseHandler(response)
				if res:
					if res.data:
						self.loaderHandler(res.data)
					if res.modules:
						self.moduleHandler(res.modules)
			else:
				print "{0} No response data".format(self.time)

	def logFile(self, fileType, file):
		h = SHA256.new()
		h.update(file)
		filename = self.time+"_"+fileType+"_"+h.hexdigest()+".bin"
		fo = open("logs/"+filename, "wb")
		fo.write(file)
		fo.close()
