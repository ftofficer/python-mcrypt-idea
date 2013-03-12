#!/usr/bin/python
import unittest
from cStringIO import StringIO

# Add build directory to search path
import os
if os.path.exists("build"):
	from distutils.util import get_platform
	import sys
	s = "build/lib.%s-%.3s" % (get_platform(), sys.version)
	s = os.path.join(os.getcwd(), s)
	sys.path.insert(0,s)

from mcrypt import *

class BaseTestCase(unittest.TestCase):
	"Base for other testcases."

	TEXT = """
       The  libmcrypt  is a data encryption library.  The library
       is thread safe  and  provides  encryption  and  decryption
       functions.   This  version  of  the  library supports many
       encryption algorithms and  encryption  modes.  Some  algo­
       rithms which are supported: SERPENT, RIJNDAEL, 3DES, GOST,
       SAFER+, CAST-256, RC2, XTEA, 3WAY, TWOFISH, BLOWFISH, ARC­
       FOUR, WAKE and more.

       OFB,  CBC,  ECB, nOFB, nCFB and CFB are the modes that all
       algorithms may function.  ECB, CBC, nCFB and nOFB  encrypt
       in  blocks but CFB and OFB in bytes (8bits). Note that CFB
       and OFB in the rest of the document  represent  the  "8bit
       CFB  or OFB" mode.  nOFB and nCFB modes represents a n-bit
       OFB/CFB mode, n is used to represent the algorithm's block
       size.   The  library  supports  an  extra  STREAM  mode to
       include some stream algorithms like WAKE or ARCFOUR."""

	PAIRS = [
			 ("rijndael-128",	"cbc"),
			 ("blowfish",		"cfb"),
			 ("twofish",		"ofb"),
			 ("tripledes",		"ecb"),
			 ("saferplus",		"nofb"),
			 ("cast-256",		"ncfb"),
			 ("wake",			"stream"),
			 ("enigma",			"stream"),
			]
	
	ERRORPAIRS = [
				  ("wake",		"cbc"),		 # Stream algo, block mode
				  ("blowfish",	"stream"),	 # Block algo, stream mode
				  ("notvalid",	"stream"),	 # Unknown algo
				  ("blowfish",	"notvalid"), # Unknown mode
				  ("notvalid",	"notvalid"), # Unknown algo & mode
				  ("stream",	"blowfish"), # Inverted
				  ("cbc",		"wake"),	 # Inverted
				 ]
	
	ALGO = {
					"rijndael-128":{
						"key_size":32,
						"key_sizes":[16,24,32],
						"iv_size":16,
						"block_size":16,
						"is_block_algorithm":1,
					},
					"blowfish":{
						"key_size":56,
						"key_sizes":[],
						"iv_size":8,
						"block_size":8,
						"is_block_algorithm":1,
					},
					"twofish":{
						"key_size":32,
						"key_sizes":[16,24,32],
						"iv_size":16,
						"block_size":16,
						"is_block_algorithm":1,
					},
					"tripledes":{
						"key_size":24,
						"key_sizes":[24],
						"iv_size":8,
						"block_size":8,
						"is_block_algorithm":1,
					},
					"saferplus":{
						"key_size":32,
						"key_sizes":[16,24,32],
						"iv_size":16,
						"block_size":16,
						"is_block_algorithm":1,
					},
					"cast-256":{
						"key_size":32,
						"key_sizes":[16,24,32],
						"iv_size":16,
						"block_size":16,
						"is_block_algorithm":1,
					},
					"wake":{
						"key_size":32,
						"key_sizes":[32],
						"iv_size":32, # Shouldn't this be 0?
						"block_size":1,
						"is_block_algorithm":0,
					},
					"enigma":{
						"key_size":13,
						"key_sizes":[],
						"iv_size":0,
						"block_size":1,
						"is_block_algorithm":0,
					},
				 }

	MODE = {
					"ecb":{
						"is_block_mode":1,
						"is_block_algorithm_mode":1,
						"has_iv":0,
					},
					"cbc":{
						"is_block_mode":1,
						"is_block_algorithm_mode":1,
						"has_iv":1,
					},
					"cfb":{
						"is_block_mode":0,
						"is_block_algorithm_mode":1,
						"has_iv":1,
					},
					"ncfb":{
						"is_block_mode":1,
						"is_block_algorithm_mode":1,
						"has_iv":1,
					},
					"ofb":{
						"is_block_mode":0,
						"is_block_algorithm_mode":1,
						"has_iv":1,
					},
					"nofb":{
						"is_block_mode":1,
						"is_block_algorithm_mode":1,
						"has_iv":1,
					},
					"stream":{
						"is_block_mode":0,
						"is_block_algorithm_mode":0,
						"has_iv":0,
					},
			}

class MCRYPTMisc(BaseTestCase):
	"Test MCRYPT type miscelaneous methods."

	def testConstructor(self):
		"Create valid objects"
		for algorithm, mode in self.PAIRS:
			MCRYPT(algorithm, mode)
	
	def testConstructorError(self):
		"Creating invalid objects must raise exception"
		for algorithm, mode in self.ERRORPAIRS:
			self.assertRaises(MCRYPTError, MCRYPT, algorithm, mode)
	
	def testGetKeySize(self):
		"Test MCRYPT.get_key_size() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.ALGO[algorithm]["key_size"]
			self.assertEqual(m.get_key_size(), val)
		
	def testGetKeySizes(self):
		"Test MCRYPT.get_key_sizes() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.ALGO[algorithm]["key_sizes"]
			self.assertEqual(m.get_key_sizes(), val)
		
	def testHasIv(self):
		"Test MCRYPT.has_iv() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.MODE[mode]["has_iv"]
			self.assertEqual(m.has_iv(), val)
		
	def testGetIvSize(self):
		"Test MCRYPT.get_iv_size() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.ALGO[algorithm]["iv_size"]
			self.assertEqual(m.get_iv_size(), val)
		
	def testGetBlockSize(self):
		"Test MCRYPT.get_block_size() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.ALGO[algorithm]["block_size"]
			self.assertEqual(m.get_block_size(), val)
	
	def testIsBlockAlgorithm(self):
		"Test MCRYPT.is_block_algorithm() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.ALGO[algorithm]["is_block_algorithm"]
			self.assertEqual(m.is_block_algorithm(), val)
	
	def testIsBlockMode(self):
		"Test MCRYPT.is_block_algorithm() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.MODE[mode]["is_block_mode"]
			self.assertEqual(m.is_block_mode(), val)
			
	def testIsBlockAlgMode(self):
		"Test MCRYPT.is_block_algorithm_mode() method"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			val = self.MODE[mode]["is_block_algorithm_mode"]
			self.assertEqual(m.is_block_algorithm_mode(), val)
	
	def testInitWrongKeySize(self):
		"Running init method with wrong key size must raise exception"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			key_size = self.ALGO[algorithm]["key_size"]+1
			self.assertRaises(ValueError, m.init, "x"*key_size)
	
class MCRYPTCrypto(BaseTestCase):
	"""Test MCRYPT type cryptography methods."""

	def testFixlength(self):
		"Check if fixlength byte is what we expected"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				m.init("x"*m.get_key_size())
				data = m.encrypt(self.TEXT, fixlength=1)
				m.reinit()
				data = m.decrypt(data)
				block_size = m.get_block_size()
				flbyte = len(self.TEXT)%block_size
				self.assertEqual(ord(data[-1]), flbyte)
	
	def testPadding(self):
		"Check if encryption padding is being done as expected"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				m.init("x"*m.get_key_size())
				data = m.encrypt(self.TEXT)
				m.reinit()
				data = m.decrypt(data)
				block_size = m.get_block_size()
				pad = "\x00"*(block_size-(len(self.TEXT)%block_size))
				self.assertEqual(data, self.TEXT+pad)
	
	def testEncrypt(self):
		"Test encryption using fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			m.init("x"*m.get_key_size())
			data = m.encrypt(self.TEXT, fixlength=1)
			m.reinit()
			data = m.decrypt(data, fixlength=1)
			self.assertEqual(data, self.TEXT)
	
	def testEncryptExactBlockSizeFixlength(self):
		"Test encryption of data with exact block size using fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				m.init("x"*m.get_key_size())
				data = m.encrypt(self.TEXT[:block_size], fixlength=1)
				m.reinit()
				data = m.decrypt(data, fixlength=1)
				self.assertEqual(data, self.TEXT[:block_size])
	
	def testEncryptExactBlockSize(self):
		"Test encryption of data with exact block size without fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				m.init("x"*m.get_key_size())
				data = m.encrypt(self.TEXT[:block_size])
				m.reinit()
				data = m.decrypt(data, fixlength=1)
				self.assertEqual(data, self.TEXT[:block_size])
	
	def testEncryptMultipleOfBlockSizeFixlength(self):
		"Test encryption of data multiple of block size using fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				m.init("x"*m.get_key_size())
				data = m.encrypt(self.TEXT[:block_size*10], fixlength=1)
				m.reinit()
				data = m.decrypt(data, fixlength=1)
				self.assertEqual(data, self.TEXT[:block_size*10])

	def testEncryptMultipleOfBlockSize(self):
		"Test encryption of data multiple of block size without fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				m.init("x"*m.get_key_size())
				data = m.encrypt(self.TEXT[:block_size*10])
				m.reinit()
				data = m.decrypt(data)
				self.assertEqual(data, self.TEXT[:block_size*10])

	def testFileFixlength(self):
		"Check if fixlength byte is what we expected with file encrypt"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				filein = StringIO(self.TEXT)
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				m.encrypt_file(filein, fileout)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				# Default is to use fixlength
				m.decrypt_file(filein, fileout, fixlength=0)
				block_size = m.get_block_size()
				flbyte = len(self.TEXT)%block_size
				self.assertEqual(ord(fileout.getvalue()[-1]), flbyte)
	
	def testFilePadding(self):
		"Check if file encryption padding is being done as expected"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				filein = StringIO(self.TEXT)
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				# Default is to use fixlength
				m.encrypt_file(filein, fileout, fixlength=0)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				# Default is to use fixlength
				m.decrypt_file(filein, fileout, fixlength=0)
				block_size = m.get_block_size()
				pad = "\x00"*(block_size-(len(self.TEXT)%block_size))
				self.assertEqual(fileout.getvalue(), self.TEXT+pad)
	
	def testFileEncrypt(self):
		"Test file encryption using fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			filein = StringIO(self.TEXT)
			fileout = StringIO()
			m.init("x"*m.get_key_size())
			m.encrypt_file(filein, fileout, fixlength=1)
			m.reinit()
			filein = StringIO(fileout.getvalue())
			fileout = StringIO()
			m.decrypt_file(filein, fileout, fixlength=1)
			self.assertEqual(fileout.getvalue(), self.TEXT)

	def testFileEncryptExactBlockSizeFixlength(self):
		"Test file encryption with exact block size using fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				filein = StringIO(self.TEXT[:block_size])
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				m.encrypt_file(filein, fileout)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				m.decrypt_file(filein, fileout)
				self.assertEqual(fileout.getvalue(), self.TEXT[:block_size])
	
	def testFileEncryptExactBlockSize(self):
		"Test file encryption with exact block size without fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				filein = StringIO(self.TEXT[:block_size])
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				m.encrypt_file(filein, fileout, fixlength=0)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				m.decrypt_file(filein, fileout, fixlength=0)
				self.assertEqual(fileout.getvalue(), self.TEXT[:block_size])
	
	def testFileEncryptMultipleOfBlockSizeFixlength(self):
		"Test file encryption with multiple of block size using fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				filein = StringIO(self.TEXT[:block_size*10])
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				m.encrypt_file(filein, fileout)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				m.decrypt_file(filein, fileout)
				self.assertEqual(fileout.getvalue(), self.TEXT[:block_size*10])
	
	def testFileEncryptMultipleOfBlockSize(self):
		"Test file encryption with multiple of block size without fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				filein = StringIO(self.TEXT[:block_size*10])
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				m.encrypt_file(filein, fileout, fixlength=0)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				m.decrypt_file(filein, fileout, fixlength=0)
				self.assertEqual(fileout.getvalue(), self.TEXT[:block_size*10])

	def testFileEncryptExactBufferblocks(self):
		"Test file encryption with exact bufferblocks without fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				filein = StringIO(self.TEXT[:block_size*10])
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				m.encrypt_file(filein, fileout, fixlength=0, bufferblocks=10)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				m.decrypt_file(filein, fileout, fixlength=0)
				self.assertEqual(fileout.getvalue(), self.TEXT[:block_size*10])

	def testFileEncryptExactBufferblocksFixlength(self):
		"Test file encryption with exact bufferblocks using fixlength"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			if m.is_block_mode():
				block_size = m.get_block_size()
				filein = StringIO(self.TEXT[:block_size*10])
				fileout = StringIO()
				m.init("x"*m.get_key_size())
				m.encrypt_file(filein, fileout, bufferblocks=10)
				m.reinit()
				filein = StringIO(fileout.getvalue())
				fileout = StringIO()
				m.decrypt_file(filein, fileout)
				self.assertEqual(fileout.getvalue(), self.TEXT[:block_size*10])

	def testFileEncrypt(self):
		"Test large file encryption"
		for algorithm, mode in self.PAIRS:
			m = MCRYPT(algorithm, mode)
			filein = StringIO(self.TEXT*10000)
			fileout = StringIO()
			m.init("x"*m.get_key_size())
			m.encrypt_file(filein, fileout, fixlength=1)
			m.reinit()
			filein = StringIO(fileout.getvalue())
			fileout = StringIO()
			m.decrypt_file(filein, fileout, fixlength=1)
			self.assertEqual(fileout.getvalue(), self.TEXT*10000)

class Misc(BaseTestCase):
	"Test miscelaneous functions."

	def testGetKeySize(self):
		"Test get_key_size() function"
		for algorithm in self.ALGO.keys():
			val = self.ALGO[algorithm]["key_size"]
			self.assertEqual(get_key_size(algorithm), val)

	def testGetKeySizes(self):
		"Test get_key_sizes() function"
		for algorithm in self.ALGO.keys():
			val = self.ALGO[algorithm]["key_sizes"]
			self.assertEqual(get_key_sizes(algorithm), val)
		
	def testGetBlockSize(self):
		"Test get_block_size() function"
		for algorithm in self.ALGO.keys():
			val = self.ALGO[algorithm]["block_size"]
			self.assertEqual(get_block_size(algorithm), val)
	
	def testIsBlockAlgorithm(self):
		"Test is_block_algorithm() function"
		for algorithm in self.ALGO.keys():
			val = self.ALGO[algorithm]["is_block_algorithm"]
			self.assertEqual(is_block_algorithm(algorithm), val)
	
	def testIsBlockMode(self):
		"Test is_block_algorithm() function"
		for mode in self.MODE.keys():
			val = self.MODE[mode]["is_block_mode"]
			self.assertEqual(is_block_mode(mode), val)
			
	def testIsBlockAlgMode(self):
		"Test is_block_algorithm_mode() function"
		for mode in self.MODE.keys():
			val = self.MODE[mode]["is_block_algorithm_mode"]
			self.assertEqual(is_block_algorithm_mode(mode), val)
	
if __name__ == "__main__":
	unittest.main()

# vim:ts=4:sw=4
