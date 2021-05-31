<!-- ![esecurity](https://raw.githubusercontent.com/billbuchanan/esecurity/master/z_associated/esecurity_graphics.jpg) -->

# Lab 2: Hashing
Objective: The key objective of this lab is to understand the range of hashing methods used, analyse the strength of each of the methods, and in the usage of salting. Overall the most popular hashing methods are: MD5 (128-bit); SHA-1 (160-bit); SHA-256 (256-bit); SHA-3 (256-bit), bcrypt (192-bit) and PBKDF2 (256-bit). The methods of bcrypt, scrypt and PBKDF2 use a number of rounds, and which significantly reduce the hashing rate. This makes the hashing processes much slower, and thus makes the cracking of hashed passwords more difficult. We will also investigate the key hash cracking tools such as hashcat and John The Ripper.
 
Open up your Ubuntu instance within vsoc.napier.ac.uk and conduct this lab.

Demo: [here](https://youtu.be/rnTLr6iUbf0)

If required, you can check the hashing methods here: https://asecuritysite.com/encryption/js10 

Examples:


* https://asecuritysite.com/encryption/kdf
* https://asecuritysite.com/encryption/aes_gcm2

## A	Hashing
In this section we will look at some fundamental hashing methods.



## H	Bcrypt
MD5 and SHA-1 produce a hash signature, but this can be attacked by rainbow tables. Bcrypt (Blowfish Crypt) is a more powerful hash generator for passwords and uses salt to create a non-recurrent hash. It was designed by Niels Provos and David Mazières, and is based on the Blowfish cipher. It is used as the default password hashing method for BSD and other systems. 

Overall it uses a 128-bit salt value, which requires 22 Base-64 characters. It can use a number of iterations, which will slow down any brute-force cracking of the hashed value. For example, “Hello” with a salt value of “$2a$06$NkYh0RCM8pNWPaYvRLgN9.” gives:
<pre>
$2a$06$NkYh0RCM8pNWPaYvRLgN9.LbJw4gcnWCOQYIom0P08UEZRQQjbfpy
</pre>

As illustrated in Figure 1, the first part is "$2a$" (or "$2b$"), and then followed by the number of rounds used. In this case is it 6 rounds which is 2<sup>6</sup> iterations (where each additional round doubles the hash time). The 128-bit (22 character) salt values comes after this, and then finally there is a 184-bit hash code (which is 31 characters). 

The slowness of bcrypt is highlighted with an AWS EC2 server benchmark using hashcat:

* Hash type: MD5 Speed/sec: 380.02M words
* Hash type: SHA1 Speed/sec: 218.86M words
* Hash type: SHA256 Speed/sec: 110.37M words
* Hash type: bcrypt, Blowfish(OpenBSD) Speed/sec: 25.86k words
* Hash type: NTLM. Speed/sec: 370.22M words

You can see that Bcrypt is almost 15,000 times slower than MD5 (380,000,000 words/sec down to only 25,860 words/sec). With John The Ripper:

* md5crypt [MD5 32/64 X2] 318237 c/s real, 8881 c/s virtual
* bcrypt ("$2a$05", 32 iterations)  25488 c/s real, 708 c/s virtual
* LM [DES 128/128 SSE2-16] 88090K c/s real, 2462K c/s virtual

where you can see that BCrypt over 3,000 times slower than LM hashes. So, although the main hashing methods are fast and efficient, this speed has a down side, in that they can be cracked easier. With Bcrypt the speed of cracking is considerably slowed down, with each iteration doubling the amount of time it takes to crack the hash with brute force. If we add one onto the number of rounds, we double the time taken for the hashing process. So, to go from 6 to 16 increase by over 1,000 (210) and from 6 to 26 increases by over 1 million (220).

The following defines a Python script which calculates a whole range of hashes [code](https://repl.it/@billbuchanan/ch03code05#main.py):

```python
# https://asecuritysite.com/encryption/hash


import sys
from hashlib import md5
import passlib.hash;

import bcrypt
import hashlib;

num = 30
repeat_n=1


salt="ZDzPE45C"
string="the boy stood on the burning deck"
salt2="1111111111111111111111"



import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

print ("Word: ",string)
print ("Salt: ",salt)



print("\nHashes")
print("SHA-1\t",hashlib.sha1(string.encode()).hexdigest())
print("SHA-256\t",hashlib.sha256(string.encode()).hexdigest())
print("SHA-512\t",hashlib.sha512(string.encode()).hexdigest())

print("MD-5:\t\t\t", md5(string.encode()).hexdigest())
print("DES:\t\t\t",  passlib.hash.des_crypt.hash(string.encode(), salt=salt[:2]))

print("Bcrypt:\t\t\t", bcrypt.kdf(string.encode(),salt=salt.encode(),desired_key_bytes=32,rounds=100 ).hex())

print("APR1:\t\t\t",  passlib.hash.apr_md5_crypt.hash(string.encode(), salt=salt))

print("PBKDF2 (SHA1):\t\t",  passlib.hash.pbkdf2_sha1.hash(string.encode(),rounds=5, salt=salt.encode()))
print("PBKDF2 (SHA-256):\t", passlib.hash.pbkdf2_sha256.hash(string,rounds=5, salt=salt.encode()))

print("LM Hash:\t\t",  passlib.hash.lmhash.hash(string.encode()))
print("NT Hash:\t\t",  passlib.hash.nthash.hash(string.encode()))
print("MS DCC:\t\t\t",  passlib.hash.msdcc.hash(string.encode(), salt))

print("LDAP (MD5):\t\t", passlib.hash.ldap_hex_md5.hash(string.encode()))
print("LDAP (SHA1):\t\t",  passlib.hash.ldap_hex_sha1.hash(string.encode()))

print("MS SQL 2000:\t\t",  passlib.hash.mssql2000.hash(string.encode()))
print("MySQL:\t\t\t",  passlib.hash.mysql41.hash(string.encode()))
print("Oracle 10:\t\t",  passlib.hash.oracle10.hash(string.encode(), user=salt))
print("Postgres (MD5):\t\t", passlib.hash.postgres_md5.hash(string.encode(), user=salt))
print("Cisco PIX:\t\t",  passlib.hash.cisco_pix.hash(string[:16].encode(), user=salt))
print("Cisco Type 7:\t\t",  passlib.hash.cisco_type7.hash(string.encode()))
```
Figure 1 Bcrypt

### H.1	
Create the hash for the word “hello” for the different methods (you only have to give the first six hex characters for the hash):



MD5:

SHA1:

SHA256:

SHA512:

DES:

Also note the number hex characters that the hashed value uses:

MD5:

Sun MD5:

SHA-1:

SHA-256:

SHA-512:



## Additional
## C.4
This uses AES and PBKDF2 for key generation:

```

from Crypto.Cipher import AES
import sys
import binascii
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

plaintext='hello how are you?'
password='qwerty123'


if (len(sys.argv)>1):
  plaintext=(sys.argv[1])
if (len(sys.argv)>2):
  password=(sys.argv[2])

def encrypt(plaintext,key, mode):
  encobj = AES.new(key, AES.MODE_GCM)
  ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
  return(ciphertext,authTag,encobj.nonce)

def decrypt(ciphertext,key, mode):
  (ciphertext,  authTag, nonce) = ciphertext
  encobj = AES.new(key,  mode, nonce)
  return(encobj.decrypt_and_verify(ciphertext, authTag))

salt = get_random_bytes(32)
key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA256)

print("GCM Mode: Stream cipher and authenticated")
print("\nMessage:\t",plaintext)
print("Key:\t\t",password)


ciphertext = encrypt(plaintext.encode(),key,AES.MODE_GCM)

print("Salt:\t\t",binascii.hexlify(salt))
print("Cipher:\t\t",binascii.hexlify(ciphertext[0]))
print("Auth Msg:\t",binascii.hexlify(ciphertext[1]))
print("Nonce:\t\t",binascii.hexlify(ciphertext[2]))


res= decrypt(ciphertext,key,AES.MODE_GCM)


print ("\n\nDecrypted:\t",res.decode())
```


Repl.it: [here](https://asecuritysite.com/encryption/aes_gcm2) Demo: [here](https://asecuritysite.com/encryption/aes_gcm2)
sudo apt-get install 7zip-full
7z e bfield.hash.7z
7z e rockyou.txt.bz2
</pre>

