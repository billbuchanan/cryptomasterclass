
## ECC Signing (ECDSA)
### A.1

```
import sys
import random
import hashlib
import libnum

from secp256k1 import curve,scalar_mult,point_add

msg="Hello"

if (len(sys.argv)>1):
  msg=(sys.argv[1])

# Alice's key pair (dA,QA)
dA = random.randint(0, curve.n-1)
QA = scalar_mult(dA,curve.g)

h=int(hashlib.sha256(msg.encode()).hexdigest(),16)

k = random.randint(0, curve.n-1)

rpoint = scalar_mult(k,curve.g)

r = rpoint[0] % curve.n

# Bob takes m and (r,s) and checks
inv_k = libnum.invmod(k,curve.n)

s = (inv_k*(h+r*dA)) % curve.n

print (f"Msg: {msg}\n\nAlice's private key={dA}\nAlice's public key={QA}\nk= {k}\n\nr={r}\ns={s}")

# To check signature

inv_s = libnum.invmod(s,curve.n)
c = inv_s
u1=(h*c) % curve.n
u2=(r*c) % curve.n
P = point_add(scalar_mult(u1,curve.g), scalar_mult(u2,QA))

res = P[0] % curve.n
print (f"\nResult r={res}")

if (res==r):
	print("Signature matches!")
```

Replit: [here](https://replit.com/@billbuchanan/basicecdsa)

### A.1	
Elliptic curve methods are often used to sign messages, and where Bob will sign a message with his private key, and where Alice can prove that he has signed it by using his public key. With ECC, we can use ECDSA, and which was used in the first version of Bitcoin. Enter the following code:

```python
from ecdsa import SigningKey,NIST192p,NIST224p,NIST256p,NIST384p,NIST521p,SECP256k1
import base64
import binascii

msg="Hello"
type = 1
cur=NIST192p


sk = SigningKey.generate(curve=cur)  # private key

vk = sk.get_verifying_key() # public key

signature = sk.sign(msg.encode())

print ("Message:\t",msg)
print ("Type:\t\t",cur.name)
print ("=========================")

print ("Signature:\t",base64.b64encode(signature))
print ("Signature:\t",binascii.hexlify(signature))
r=binascii.hexlify(signature)[0:32]
s=binascii.hexlify(signature)[32:64]
print ("r=\t",r)
print ("s=\t",s)

print ("=========================")

print ("Signatures match:\t",vk.verify(signature, msg.encode()))
```

Replit: [here](https://replit.com/@billbuchanan/signing01#main.py)

What are the signatures (you only need to note the first four characters) for a message of “Bob”, for the curves of NIST192p, NIST521p and SECP256k1:

NIST192p:

NIST521p:

SECP256k1:


By searching on the Internet, can you find in which application areas that SECP256k1 is used?

How many bytes does r and s have?

