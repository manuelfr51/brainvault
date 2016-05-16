from aespython import key_expander, aes_cipher, cbc_mode
from bitcoin.main import sha256

class AES:
	def __init__(self, password, iv = None):
		self.key = bytearray(sha256(password))
		self.iv = list(bytearray(os.urandom(32))) if iv is None else iv

	def encrypt(self, text):
		enc = None
		aes_cipher_256 = aes_cipher.AESCipher(self.key)
		aes_cbc_256 = cbc_mode.CBCMode(aes_cipher_256, 16)
		aes_cbc_256.set_iv(self.iv)
		byte_array = bytearray(text)
		partitions = [byte_array[i:i+16] for i in range(0, len(byte_array), 16)]
		enc_bytes = []
		for p in partitions:
			if len(p) > 0:
				if len(p) < 16:
					for i in range(0, (16 - len(p))):
						p.append(16 - len(p))
				enc_bytes += aes_cbc_256.encrypt_block(p)
		return enc_bytes

	def decrypt(self, text):
		dec = None
		aes_cipher_256 = aes_cipher.AESCipher(self.key)
		aes_cbc_256 = cbc_mode.CBCMode(aes_cipher_256, 16)
		aes_cbc_256.set_iv(self.iv)
		dec_bytes = []
		partitions = [text[i:i+16] for i in range(0, len(text), 16)]
		for p in partitions:
			if len(p) > 0:
				dec_bytes += aes_cbc_256.decrypt_block(p)
		return dec_bytes

	def get_iv_str(self):
		return self.iv
