from django.shortcuts import render
from django.http import HttpResponse,JsonResponse
import timeit
from cryptography.fernet import Fernet
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import nacl.utils
from nacl.public import PrivateKey, Box, SealedBox
import nacl.secret
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

'''
secp_k = generate_key()
prvhex = secp_k.to_hex()
pubhex = secp_k.public_key.format(True).hex()
decrypt(prvhex, encrypt(pubhex, data))
'''


def performSearch(tezt):
    return True


    arrayTest = ["X"]*1000


##  if __name__ == "__main__":
 ##   res =  timeit.timeit("performSearch(arrayTest)","from __main__ import performSearch, arrayTest",number=10)
##
##


# Create your views here.
def index(request):
   
    res = 4
    #encryptedText = crypto_fernet_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet");
    #if __name__ == "__main__":
    #res =  timeit.timeit(stmt="performSearch(arrayTest)",setup="from __main__ import performSearch, arrayTest",number=10)
    fernet_encrypt_time = timeit.timeit(lambda: crypto_fernet_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    chacha_encrypt_time = timeit.timeit(lambda: chacha20algo_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    ecciespy_encrypt_time = timeit.timeit(lambda: ecciespy_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    AES_GCM_ecnrypt_time = timeit.timeit(lambda: AES_GCM_ecnrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    AES_CCM_ecnrypt_time = timeit.timeit(lambda: AES_CCM_ecnrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    cipherAESEncrypt_time = timeit.timeit(lambda: cipherAESEncrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    cipherChaCha20_time = timeit.timeit(lambda: cipherChaCha20("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    cryptography_kdf_time = timeit.timeit(lambda: cryptography_kdf(),number=200)
    cryptoContactKDFHMAC_time = timeit.timeit(lambda: cryptoContactKDFHMAC(),number=200)   
    NACL_box_ecnrypt_time = timeit.timeit(lambda: NACL_box_ecnrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    NACL_sealedBox_encrypt_time = timeit.timeit(lambda: NACL_sealedBox_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    NACL_secret_encrypt_time = timeit.timeit(lambda: NACL_secret_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    pycryptodomeAES_encrypt_time = timeit.timeit(lambda: pycryptodomeAES_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=200)
    #pycryptodomeRSA_encrypt_time = timeit.timeit(lambda: pycryptoDomeRSA_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=10)

    #cryptography_RSA_encrypt_time = timeit.timeit(lambda: cryptography_RSA_encrypt("netcryppto_fernetcrypto_fernetcrypto_fernetcrypto_fernet"),number=2000)
    #return HttpResponse(fernet_encrypt_time, chacha_encrypt_time) pysodium_aead_chacha20poly1305
    val = chacha_encrypt_time   
    return JsonResponse({'PyCryptoDome RSA Time':"This is paused Coz it take more than a minute",'PyCryptoDome AES Time':str(round(pycryptodomeAES_encrypt_time,3))+' seconds','NACL Secret Time':str(round(NACL_secret_encrypt_time,3))+' seconds','NACL Sealed Box time':NACL_sealedBox_encrypt_time,'NACL Box duration':NACL_box_ecnrypt_time,'Cipher ChaCha20':cipherChaCha20_time,'Cipher AES Duration':cipherAESEncrypt_time,'Fernet Duration':fernet_encrypt_time , 'ChaCha20 Duration': val,'AESCCM Duration':AES_CCM_ecnrypt_time,'AESGCM Duration':AES_GCM_ecnrypt_time,'Elliptic Curve IES': ecciespy_encrypt_time,'Cryptography KDF Duration':cryptography_kdf_time,'Crypto Contact KDFHMAC':cryptoContactKDFHMAC_time})




   #return render(request, 'crypto_gui.html')
def crypto_fernet_encrypt(text):
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(bytes(text,'utf-8'))
    f.decrypt(token)
    return token 

def crypto_fernet_decrypt(text):
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(bytes(text,'utf-8'))
    #f.decrypt(token)
    return token        

def chacha20algo_encrypt(text):
    data = bytes(text,'utf-8')
    aad = bytes("Research",'utf-8')
    key = ChaCha20Poly1305.generate_key()  
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, data, aad)
    plain_text = chacha.decrypt(nonce, ct, aad)
    return True  

def AES_GCM_ecnrypt(text):
    data = bytes(text,'utf-8')
    aad = bytes("Research",'utf-8')
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, aad)
    aesgcm.decrypt(nonce, ct, aad)
    return True  
 
def AES_CCM_ecnrypt(text):
    data = bytes(text,'utf-8')
    aad = bytes("Research",'utf-8')
    key = AESCCM.generate_key(bit_length=128)
    aesccm = AESCCM(key)
    nonce = os.urandom(12)
    ct = aesccm.encrypt(nonce, data, aad)
    aesccm.decrypt(nonce, ct, aad)
    return True 

def ecciespy_encrypt(text):
    eth_k = generate_eth_key()
    prvhex = eth_k.to_hex()
    pubhex = eth_k.public_key.to_hex()
    data = bytes(text,'utf-8')
    decrypt(prvhex, encrypt(pubhex, data))
    return True 

def cryptography_RSA_encrypt(text):
    private_key = rsa.generate_private_key(
    public_exponent=3,
    key_size=2048,
    backend=default_backend()
    )
    public_key = private_key.public_key()
    message = bytes(text, 'utf-8')
    ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None ))
    plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None ))
    return True 

def cryptography_kdf():
    backend = default_backend()
    # Salts should be randomly generated
    salt = os.urandom(16)
    # derive
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=10,
    backend=backend)
    key = kdf.derive(b"my great password")
    # verify
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=10,
    backend=backend)
    kdf.verify(b"my great password", key)
    return True 


def cryptoContactKDFHMAC():
    backend = default_backend()
    salt = os.urandom(16)
    otherinfo = b"concatkdf-example"
    ckdf = ConcatKDFHMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    otherinfo=otherinfo,
    backend=backend
    )
    key = ckdf.derive(b"input key")
    ckdf = ConcatKDFHMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    otherinfo=otherinfo,
    backend=backend
    )
    ckdf.verify(b"input key", key)
    return True

def cipherAESEncrypt(text):
    BS = 16
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    unpad = lambda s : s[0:-ord(s[-1])]
    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    text = pad(text)
    ct = encryptor.update(bytes(text,'utf-8')) + encryptor.finalize()
    decryptor = cipher.decryptor()
    decryptor.update(ct) + decryptor.finalize()
    return True

def cipherChaCha20(text):
    key = os.urandom(32)
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(text,'utf-8'))
    decryptor = cipher.decryptor()
    decryptor.update(ct)
    return True

def NACL_box_ecnrypt(text):
    # Generate Bob's private key, which must be kept secret
    skbob = PrivateKey.generate()
    # Bob's public key can be given to anyone wishing to se
    # Bob an encrypted message
    pkbob = skbob.public_key
    # Alice does the same and then Alice and Bob exchange p
    skalice = PrivateKey.generate()
    pkalice = skalice.public_key
    # Bob wishes to send Alice an encrypted message so Bob
    # his private key and Alice's public key
    bob_box = Box(skbob, pkalice)
    # This is our message to send, it must be a bytestring
    # as just a binary blob of data.
    message = bytes(text,'utf-8')
    # Encrypt our message, it will be exactly 40 bytes long
    # original message as it stores authentication inform
    # nonce alongside it.
    encrypted = bob_box.encrypt(message)
    # This is a nonce, it *MUST* only be used once, but it
    # secret and can be transmitted or stored alongside t
    # good source of nonces are just sequences of 24 rand
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    encrypted = bob_box.encrypt(message, nonce)
    # Alice creates a second box with her private key to de
    alice_box = Box(skalice, pkbob)
    # Decrypt our message, an exception will be raised if t
    # tampered with or there was otherwise an error.
    plaintext = alice_box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))
    return True

def NACL_sealedBox_encrypt(text):
    # Generate Bob's private key, as we've done in the Box example
    skbob = PrivateKey.generate()
    pkbob = skbob.public_key
    # Alice wishes to send a encrypted message to Bob,
    # but prefers the message to be untraceable
    sealed_box = SealedBox(pkbob)
    # This is Alice's message
    message = bytes(text,'utf-8')
    # Encrypt the message, it will carry the ephemeral key public part
    # to let Bob decrypt it
    encrypted = sealed_box.encrypt(message)
    #Now, Bob wants to read the secret message he just received; therefore he must create a SealedBox using his own
    #private key:
    unseal_box = SealedBox(skbob)
    # decrypt the received message
    plaintext = unseal_box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))
    return True 

def NACL_secret_encrypt(text):
    message = bytes(text,'utf-8')
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
# This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(message, nonce)
    ctext = encrypted.ciphertext
    plaintext = box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))
    return True 

def simplecryptoSymmetricEncryption(text):
    # Generates a new AES-256 random key.
    key = AesKey()
    m = key.encrypt(text)
    key.decrypt(m)
    return True


def pycryptodomeAES_encrypt(text):
    data = bytes(text,'utf-8')
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    file_out = open("encrypted.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_in = open("encrypted.bin", "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    nonce = cipher.nonce
    # let's assume that the key is somehow available again
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    #data = cipher.decrypt_and_verify(ciphertext, tag)
    return True 

def pycryptoDomeRSA_encrypt(text):
    key = RSA.generate(2048)
    private_key = key.export_key()
    #file_out = open("private.pem", "wb")
    #file_out.write(private_key)

    public_key = key.publickey().export_key()
    # file_out = open("receiver.pem", "wb")
    #file_out.write(public_key)
    recipient_key = public_key
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(text)
    
    enc_session_key, nonce, tag, ciphertext = \
       [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return True 

def pyOCB_encrypt(text):
    aes = AES(128)
    ocb = OCB(aes)
    key = bytearray().fromhex('A45F5FDEA5C088D1D7C8BE37CABC8C5C')
    ocb.setKey(key)
    nonce = bytearray(range(16))
    ocb.setNonce(nonce)
    plaintext = bytearray('The Magic Words are Squeamish Ossifrage')
    header = bytearray('Recipient: john.doe@example.com')
    (tag,ciphertext) = ocb.encrypt(plaintext, header)
    (is_authentic, plaintext2) = ocb.decrypt(header, ciphertext, tag)
    return True
