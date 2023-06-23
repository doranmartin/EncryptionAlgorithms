from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
cipher_enc = AES.new(key, AES.MODE_EAX)
nonce = cipher_enc.nonce
plaintext = b'NO MORE APPLES IN THE VENDING MACHINE PLEASE!!!'

print("Original message = ", plaintext)

ciphertext, tag = cipher_enc.encrypt_and_digest(plaintext)

print('Encrypted message = ', ciphertext)

cipher_dec = AES.new(key, AES.MODE_EAX, nonce)
decrypted_data = cipher_dec.decrypt(ciphertext)

print('Decrypted message = ', decrypted_data)
