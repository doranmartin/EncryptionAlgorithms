from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
BLOCK_SIZE = 32

key = get_random_bytes(8)
cipher_encrypt = DES.new(key, DES.MODE_ECB)
cipher_decrypt = DES.new(key, DES.MODE_ECB)
plaintext = b'NO MORE APPLES IN THE VENDING MACHINE PLEASE!!!'

print("Original message = ", plaintext)

msg = cipher_encrypt.encrypt(pad(plaintext, BLOCK_SIZE))

print('Encrypted message = ', msg)

decrypted_data = cipher_decrypt.decrypt(msg)

print('Decrypted message = ', unpad(decrypted_data, BLOCK_SIZE))
