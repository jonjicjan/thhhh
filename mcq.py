"""
x=5
for i in range(0,11):
    print(f"{x} X {i} = {x*i}")
    
def fact(n):
    if n==0 or n==1:
        return 1
    else:
        return n*fact(n-1) 
print(fact(5))    


t=10
sum=0
while(t<0):
    sum=t+sum
    sum+=1 
print(sum)    




def rsa(p,q):
    n=p*q
    fi_n=(p-1)*(q-1)
    e=7
    k=int(input(" enter the value of k : :"))  
    d=(1+(k*fi_n))/e
    message=int(input("Enter the message that you want to encrypt :-"))
    encrypt=(message**e)%n
    decrypt=(encrypt**d)%n

    print(f"The value of p is :{p}")
    print(f"The value of q is :{q}")
    print(f"The value of e is :{e}")
    print(f"The value of d is :{d}")
    print(f"The value of message that is to be encrypted : {message}")
    print(f"The encrpypted vlaue is :{encrypt}")
    print(f"The decrpypted value which is message :{decrypt}")
print(rsa(3,5))





def diffie(p,q):
    pvt_key_of_A=27
    pvt_key_of_B=42
    
    pub_key_of_A=(q**pvt_key_of_A)%p
    pub_key_of_B=(q**pvt_key_of_B)%p
    
    k1=(pub_key_of_A**pvt_key_of_B)%p
    k2=(pub_key_of_B**pvt_key_of_A)%p
    
    
    print(f"value of p is :{p}")
    print(f"value of q is :{q}")
    print(f"Private key of A is :{pvt_key_of_A}")
    print(f"Private key of b is :{pvt_key_of_B}")
    print(f"Public key of A is :{pub_key_of_A}")
    print(f"Public key of B is :{pub_key_of_B}")

    if k1 == k2:
        print("Key exchange successfuly")
        print(f"The value of p is :{k1}")
        print(f"The value of q is :{k2}")
    else:
        print("key could not exchange,try again some error occur")    
        
 
print(diffie(11,7))


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def encrypt_message(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()

key = os.urandom(16)
original_message = "Mohammad Umar Khan"
print("Original Message is:", original_message)

encrypted_message = encrypt_message(key, original_message)
print("Encrypted message is:", encrypted_message)

decrypted_message = decrypt_message(key, encrypted_message)
print("Decrypted message is:", decrypted_message)


    
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plain_text, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    cipher_text = cipher.encrypt(padded_text)
    return iv + cipher_text

# AES decryption function
def aes_decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    actual_cipher_text = cipher_text[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_text = cipher.decrypt(actual_cipher_text)
    plain_text = unpad(decrypted_padded_text, AES.block_size)
    return plain_text.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Define a key (must be 16, 24, or 32 bytes long)
    key = b'Sixteen byte key'
    
    
    plain_text = "Hello, World!"
    print("plain text :",plain_text)
    encrypted_text = aes_encrypt(plain_text, key)
    print(f"Encrypted: {encrypted_text.hex()}")
    decrypted_text = aes_decrypt(encrypted_text, key)
    print(f"Decrypted: {decrypted_text}")






def pad(data):
    block_size = AES.block_size
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding
def unpad(data):
    padding = data[-1]
    return data[:-padding]
def generate_key(password, salt):
    key = PBKDF2(password, salt, dkLen=32)  # AES-256 key size (32 bytes)
    return key

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os


def encrypt(plaintext, password):
    salt = get_random_bytes(16)
    iv = get_random_bytes(AES.block_size)
    key = generate_key(password, salt)
    plaintext = pad(plaintext.encode('utf-8'))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    encrypted_data = salt + iv + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')
def decrypt(encrypted_data, password):
    encrypted_data = base64.b64decode(encrypted_data)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_data)
    return decrypted_data.decode('utf-8')
if __name__ == '__main__':
    password = input("Enter password for encryption/decryption: ")
    plaintext = input("Enter plaintext to encrypt: ")
    encrypted_text = encrypt(plaintext, password)
    print("Encrypted Text:", encrypted_text)

    decrypted_text = decrypt(encrypted_text, password)
    print("Decrypted Text:", decrypted_text)
"""





from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def encrypt_message(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()

key = os.urandom(16)
original_message = "Mohammad Umar Khan"
print("Original Message is:", original_message)

encrypted_message = encrypt_message(key, original_message)
print("Encrypted message is:", encrypted_message)

decrypted_message = decrypt_message(key, encrypted_message)
print("Decrypted message is:", decrypted_message)
















