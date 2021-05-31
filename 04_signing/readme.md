
### D.3	
Elliptic curve methods are often used to sign messages, and where Bob will sign a message with his private key, and where Alice can prove that he has signed it by using his public key. With ECC, we can use ECDSA, and which was used in the first version of Bitcoin. Enter the following code:

```python
from ecdsa import SigningKey,NIST192p,NIST224p,NIST256p,NIST384p,NIST521p,SECP256k1
import base64
import sys

msg="Hello"
type = 1
cur=NIST192p


sk = SigningKey.generate(curve=cur) 

vk = sk.get_verifying_key()

signature = sk.sign(msg.encode())

print ("Message:\t",msg)
print ("Type:\t\t",cur.name)
print ("=========================")

print ("Signature:\t",base64.b64encode(signature))

print ("=========================")

print ("Signatures match:\t",vk.verify(signature, msg.encode()))
```

What are the signatures (you only need to note the first four characters) for a message of “Bob”, for the curves of NIST192p, NIST521p and SECP256k1:

NIST192p:

NIST521p:

SECP256k1:


By searching on the Internet, can you find in which application areas that SECP256k1 is used?


What do you observe from the different hash signatures from the elliptic curve methods?

