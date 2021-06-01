<!-- ![esecurity](https://raw.githubusercontent.com/billbuchanan/esecurity/master/z_associated/esecurity_graphics.jpg) -->

# Lab 1: Symmetric Key
Objective: The key objective of this lab is to understand the range of symmetric key methods used within symmetric key encryption. We will introduce block ciphers, stream ciphers and padding. 

## A Bit operations, hex and Base-64

```python
import binascii
import base64

str="hello"
hex_str=binascii.hexlify(str.encode())
base64_str= base64.b64encode(str.encode())
print(f"String {str}")
print (f"Base64: {base64_str}")
print(f"Hex: {hex_str}")

base64_str="Z29vZGJ5ZQ=="
byte_str=base64.b64decode(base64_str)
hex_str= binascii.hexlify(byte_str)
print(f"\nBase64: {base64_str}")
print (f"String: {byte_str.decode()}")
print(f"Hex: {hex_str}")

bin_str=b"hello"
hex_str=binascii.hexlify(bin_str)
base64_str= base64.b64encode(bin_str)
print(f"\nBinary: {bin_str}")
print (f"Base64: {base64_str}")
print(f"Hex: {hex_str}")


hex_str=b"666F7874726F74"
byte_str=binascii.unhexlify(hex_str)
base64_str= base64.b64encode(byte_str)
print(f"\nHex: {hex_str}")
print(f"Bytes: {byte_str}")
print (f"Base64: {base64_str}")
print(f"String: {byte_str.decode()}")
```

Replit: [here](https://replit.com/@billbuchanan/hexbase64)

Can you complete the following:

| String | Base64 | Hex |
|-----------|-----------|-----------|
| “hello”   |    | |
| “inkwell”  |  |  |
| 	   |   b3BhbA==  | 
|  	   |  |  6469616D6F6E64  |


and:

```python
import sys

val1="00110101"
val2="00110111"

if (len(sys.argv)>1):
        val1=sys.argv[1]


if (len(sys.argv)>2):
        val2=sys.argv[2]

def nor(p, q):
    return ~ (p | q) & 0xff;

def nand(p, q):
    return ~(p & q) & 0xff;

dec1=int(val1,2)
dec2=int(val2,2)

print ("Decimal form:\t",bin(dec1)[2:10].rjust(8,'0'))
print ("Decimal form:\t",bin(dec2)[2:10].rjust(8,'0'))

print ("\nResult:")
print ("--------------------")
print ("Bitwise AND:\t",bin(dec1 & dec2)[2:10].rjust(8,'0'))
print ("Bitwise NAND:\t",bin(nand(dec1,dec2))[2:10].rjust(8,'0'))
print ("Bitwise OR:\t",bin(dec1 | dec2)[2:10].rjust(8,'0'))

print ("Bitwise NOR:\t",bin(nor(dec1,dec2))[2:10].rjust(8,'0'))

print ("Bitwise XOR:\t",bin(dec1 ^ dec2)[2:10].rjust(8,'0'))
```
Replit: [here](https://replit.com/@billbuchanan/binval)

## B	Python Coding (ECB)

### B.1 ECB Mode
In this part of the lab, we will investigate the usage of Python code to perform different padding methods and using AES. In the first example we will generate a 256-bit AES encryption key and use ECB mode. The code should be:

```python
from Crypto.Cipher import AES
import hashlib
import sys
import binascii
import Padding

val='hello'
password='hello'

plaintext=val

def encrypt(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))

key = hashlib.sha256(password.encode()).digest()


plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode='CMS')

print("After padding (CMS): ",binascii.hexlify(bytearray(plaintext.encode())))

ciphertext = encrypt(plaintext.encode(),key,AES.MODE_ECB)
print("Cipher (ECB): ",binascii.hexlify(bytearray(ciphertext)))

plaintext = decrypt(ciphertext,key,AES.MODE_ECB)

plaintext = Padding.removePadding(plaintext.decode(),mode='CMS')
print("  decrypt: ",plaintext)
```

The Repl.it code is [here](https://repl.it/@billbuchanan/sma02#main.py)

Now update the code so that you can enter a string and the program will show the cipher text. The format will be something like:

```
python cipher01.py hello mykey
```

where “hello” is the plain text, and “mykey” is the key.  A possible integration is:

```python
import sys

if (len(sys.argv)>1):
	val=sys.argv[1]

if (len(sys.argv)>2):
	password=sys.argv[2]
```

Now determine the cipher text for the following (the first example has already been completed):

| Message | Key | CMS Cipher
|-----------|-----------|-----------|
| “hello” | “hello123” | 0a7ec77951291795bac6690c9e7f4c0d
| “inkwell”	| “orange” |  | 
| “security”	| “qwerty”| | 
|  “Africa”	| “changeme”| | 
	
### B.2 Decrypting ciphertext
Now modify your coding for 256-bit AES ECB encryption, so that you can enter the cipher text, and an encryption key, and the code will decrypt to provide the result. You should use CMS for padding. With this, determine the plaintext for the following (note, all the plain text values are countries around the World):

| CMS Cipher (256-bit AES ECB) |		Key 	|	Plain text |
|-----------|-----------|-----------|
| b436bd84d16db330359edebf49725c62 |	“hello” | |
| 4bb2eb68fccd6187ef8738c40de12a6b |	“ankle” | |
| 029c4dd71cdae632ec33e2be7674cc14 |	“changeme”| |
| d8f11e13d25771e83898efdbad0e522c |	“123456”| |

Now update your program, so that it takes a cipher string in Base-64 and converts it to a hex string and then decrypts it. From this now decrypt the following Base-64 encoded cipher streams (which should give countries of the World):


| CMS Cipher (256-bit AES ECB)|		Key 	|	Plain text |
|-----------|-----------|-----------|
| /vA6BD+ZXu8j6KrTHi1Y+w==	| “hello”|  | 	
| nitTRpxMhGlaRkuyXWYxtA==| 	“ankle”	 |  | 
| irwjGCAu+mmdNeu6Hq6ciw==| 	“changeme” |  | 
| 5I71KpfT6RdM/xhUJ5IKCQ==| 	“123456” |  | 
	
PS … remember to add "import base64".

### A.3	Catching exceptions
If we try “1jDmCTD1IfbXbyyHgAyrdg==” with a passphrase of “hello”, we should get a country. What happens when we try the wrong passphrase?

Output when we use “hello”:

Output when we use “hello1”:



Now catch the exception with an exception handler:

```python
try:
	plaintext = Padding.removePadding(plaintext,mode='CMS')
	print ("  decrypt: "+plaintext)
except:
	print("Error!")
```

Now implement a Python program which will try various keys for a cipher text input, and show the decrypted text. The keys tried should be:

["hello","ankle","changeme","123456"]

Run the program and try to crack:
```
1jDmCTD1IfbXbyyHgAyrdg==
```

What is the password:

## B AES Modes
### B.1 Modes
AES has a number of modes, including CBC, CTR and OFB. In the following code, we will implement these block ciphers:

```python
# https://asecuritysite.com/encryption/aes_modes
from Crypto.Cipher import AES
import hashlib
import sys
import binascii
import Padding

val='hello'
password='hello'
ival=10

if (len(sys.argv)>1):
	val=sys.argv[1]

if (len(sys.argv)>2):
	password=str(sys.argv[2])

if (len(sys.argv)>3):
	ival=int(sys.argv[3])

plaintext=val

def encrypt(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))

def encrypt2(plaintext,key, mode,iv):
	encobj = AES.new(key,mode,iv)
	return(encobj.encrypt(plaintext))

def decrypt2(ciphertext,key, mode,iv):
	encobj = AES.new(key,mode,iv)
	return(encobj.decrypt(ciphertext))


key = hashlib.sha256(password.encode()).digest()

iv= hex(ival)[2:8].zfill(16)



print ("IV: "+iv)	


plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)
print ("Input data (CMS): "+binascii.hexlify(plaintext.encode()).decode())

ciphertext = encrypt(plaintext.encode(),key,AES.MODE_ECB)
print ("Cipher (ECB): "+binascii.hexlify(bytearray(ciphertext)).decode())


plaintext = decrypt(ciphertext,key,AES.MODE_ECB)
plaintext = Padding.removePadding(plaintext.decode(),mode=0)
print ("  decrypt: "+plaintext)


plaintext=val
plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)

ciphertext = encrypt2(plaintext.encode(),key,AES.MODE_CBC,iv.encode())
print ("Cipher (CBC): "+binascii.hexlify(bytearray(ciphertext)).decode())

plaintext = decrypt2(ciphertext,key,AES.MODE_CBC,iv.encode())
plaintext = Padding.removePadding(plaintext.decode(),mode=0)
print ("  decrypt: "+plaintext)



plaintext=val
plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)

ciphertext = encrypt2(plaintext.encode(),key,AES.MODE_CFB,iv.encode())
print ("Cipher (CFB): "+binascii.hexlify(bytearray(ciphertext)).decode())

plaintext = decrypt2(ciphertext,key,AES.MODE_CFB,iv.encode())
plaintext = Padding.removePadding(plaintext.decode(),mode=0)
print ("  decrypt: "+plaintext)



plaintext=val
plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)

ciphertext = encrypt2(plaintext.encode(),key,AES.MODE_OFB,iv.encode())
print ("Cipher (OFB): "+binascii.hexlify(bytearray(ciphertext)).decode())

plaintext = decrypt2(ciphertext,key,AES.MODE_OFB,iv.encode())
plaintext = Padding.removePadding(plaintext.decode(),mode=0)
print ("  decrypt: "+plaintext)
```

Replit: [here](https://replit.com/@billbuchanan/aesmodes) Demo: [here](https://asecuritysite.com/encryption/aes_modes)

### B.2 
Enter a long stream of the same character for the plain text, such as: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'. What can you observe?

* AES Modes: https://asecuritysite.com/encryption/aes_modes

## C AES GCM Mode
### C.1
While block ciphers can be slow to encrypt and encrypt, a stream cipher can be processed faster. In this case, we will use GCM to convert to a cipher, and will not need any padding. 

```python
from Crypto.Cipher import AES
import hashlib
import sys
import binascii


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

key = hashlib.sha256(password.encode()).digest()

print("GCM Mode: Stream cipher and authenticated")
print("\nMessage:\t",plaintext)
print("Key:\t\t",password)


ciphertext = encrypt(plaintext.encode(),key,AES.MODE_GCM)

print("Cipher:\t\t",binascii.hexlify(ciphertext[0]))
print("Auth Msg:\t",binascii.hexlify(ciphertext[1]))
print("Nonce:\t\t",binascii.hexlify(ciphertext[2]))


res= decrypt(ciphertext,key,AES.MODE_GCM)


print ("\n\nDecrypted:\t",res.decode())
```


Repl.it: [here](https://replit.com/@billbuchanan/aesgcm-1) Demo: [here](https://asecuritysite.com/encryption/aes_gcm)

## Sample answers

Sample answers:[here](https://github.com/billbuchanan/cryptomasterclass/blob/master/unit02_symmetric/lab/possible_ans.md)


Answers:
```
    germany
    france
    england
    scotland
```

Possible solution for B.2:

```python
from Crypto.Cipher import AES
import hashlib
import sys
import binascii
import Padding

val='fox'
password='hello'
cipher='b436bd84d16db330359edebf49725c62'

import sys

if (len(sys.argv)>1):
	cipher=(sys.argv[1])
if (len(sys.argv)>2):
	password=(sys.argv[2])

plaintext=val

def encrypt(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))

key = hashlib.sha256(password.encode()).digest()


ciphertext=binascii.unhexlify(cipher)

plaintext = decrypt(ciphertext,key,AES.MODE_ECB)
print ('Cipher: '+ cipher)
print ('Password: '+ password)

plaintext = Padding.removePadding(plaintext.decode(),blocksize=Padding.AES_blocksize,mode='CMS')

print ("  decrypt: "+plaintext)
```

/vA6BD+ZXu8j6KrTHi1Y+w== - italy

```python
from Crypto.Cipher import AES
import hashlib
import sys
import binascii
import Padding
import base64

val='fox'
password='hello'
cipher=''

import sys

if (len(sys.argv)>1):
	cipher=(sys.argv[1])
if (len(sys.argv)>2):
	password=(sys.argv[2])

plaintext=val

def encrypt(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))

key = hashlib.sha256(password.encode()).digest()

cipher='/vA6BD+ZXu8j6KrTHi1Y+w=='

ciphertext = base64.b64decode(cipher)
plaintext = decrypt(ciphertext,key,AES.MODE_ECB)
print (plaintext)
plaintext = Padding.removePadding(plaintext.decode(),blocksize=Padding.AES_blocksize,mode='CMS')
print ("  decrypt: "+plaintext)
```
