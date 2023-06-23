from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
BLOCK_SIZE = 32


key = DES3.adjust_key_parity(get_random_bytes(24))

cipher_enc = DES3.new(key, DES3.MODE_ECB)
cipher_dec = DES3.new(key, DES3.MODE_ECB)

plaintext = b'NO MORE APPLES IN THE VENDING MACHINE PLEASE!!!'

print("Original message = ", plaintext)

msg = cipher_enc.encrypt(pad(plaintext, BLOCK_SIZE))

print('Encrypted message = ', msg)

decrypted_data = cipher_dec.decrypt(msg)

print('Decrypted message = ', unpad(decrypted_data, BLOCK_SIZE))
