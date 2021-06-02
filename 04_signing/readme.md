
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




## C	PGP
### C.1	
The following is a PGP key pair. Using https://asecuritysite.com/encryption/pgp, can you determine the owner of the keys:
```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v4.4.5
Comment: https://openpgpjs.org

xk0EXEOYvQECAIpLP8wfLxzgcolMpwgzcUzTlH0icggOIyuQKsHM4XNPugzU
X0NeaawrJhfi+f8hDRojJ5Fv8jBI0m/KwFMNTT8AEQEAAc0UYmlsbCA8Ymls
bEBob21lLmNvbT7CdQQQAQgAHwUCXEOYvQYLCQcIAwIEFQgKAgMWAgECGQEC
GwMCHgEACgkQoNsXEDYt2ZjkTAH/b6+pDfQLi6zg/Y0tHS5PPRv1323cwoay
vMcPjnWq+VfiNyXzY+UJKR1PXskzDvHMLOyVpUcjle5ChyT5LOw/ZM5NBFxD
mL0BAgDYlTsT06vVQxu3jmfLzKMAr4kLqqIuFFRCapRuHYLOjw1gJZS9p0bF
S0qS8zMEGpN9QZxkG8YEcH3gHxlrvALtABEBAAHCXwQYAQgACQUCXEOYvQIb
DAAKCRCg2xcQNi3ZmMAGAf9w/XazfELDG1W35l2zw12rKwM7rK97aFrtxz5W
XwA/5gqoVP0iQxklb9qpX7RVd6rLKu7zoX7F+sQod1sCWrMw
=cXT5
-----END PGP PUBLIC KEY BLOCK-----

-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.4.5
Comment: https://openpgpjs.org

xcBmBFxDmL0BAgCKSz/MHy8c4HKJTKcIM3FM05R9InIIDiMrkCrBzOFzT7oM
1F9DXmmsKyYX4vn/IQ0aIyeRb/IwSNJvysBTDU0/ABEBAAH+CQMIBNTT/OPv
TJzgvF+fLOsLsNYP64QfNHav5O744y0MLV/EZT3gsBwO9v4XF2SsZj6+EHbk
O9gWi31BAIDgSaDsJYf7xPOhp8iEWWwrUkC+jlGpdTsGDJpeYMIsVVv8Ycam
0g7MSRsL+dYQauIgtVb3dloLMPtuL59nVAYuIgD8HXyaH2vsEgSZSQn0kfvF
+dWeqJxwFM/uX5PVKcuYsroJFBEO1zas4ERfxbbwnsQgNHpjdIpueHx6/4EO
b1kmhOd6UT7BamubY7bcma1PBSv8PH31Jt8SzRRiaWxsIDxiaWxsQGhvbWUu
Y29tPsJ1BBABCAAfBQJcQ5i9BgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIeAQAK
CRCg2xcQNi3ZmORMAf9vr6kN9AuLrOD9jS0dLk89G/XfbdzChrK8xw+Odar5
V+I3JfNj5QkpHU9eyTMO8cws7JWlRyOV7kKHJPks7D9kx8BmBFxDmL0BAgDY
lTsT06vVQxu3jmfLzKMAr4kLqqIuFFRCapRuHYLOjw1gJZS9p0bFS0qS8zME
GpN9QZxkG8YEcH3gHxlrvALtABEBAAH+CQMI2Gyk+BqVOgzgZX3C80JRLBRM
T4sLCHOUGlwaspe+qatOVjeEuxA5DuSs0bVMrw7mJYQZLtjNkFAT92lSwfxY
gavS/bILlw3QGA0CT5mqijKr0nurKkekKBDSGjkjVbIoPLMYHfepPOju1322
Nw4V3JQO4LBh/sdgGbRnwW3LhHEK4Qe70cuiert8C+S5xfG+T5RWADi5HR8u
UTyH8x1h0ZrOF7K0Wq4UcNvrUm6c35H6lClC4Zaar4JSN8fZPqVKLlHTVcL9
lpDzXxqxKjS05KXXZBh5wl8EGAEIAAkFAlxDmL0CGwwACgkQoNsXEDYt2ZjA
BgH/cP12s3xCwxtVt+Zds8NdqysDO6yve2ha7cc+Vl8AP+YKqFT9IkMZJW/a
qV+0VXeqyyru86F+xfrEKHdbAlqzMA==
=5NaF
-----END PGP PRIVATE KEY BLOCK-----
```

### C.2	
Using the code at the following link, generate a key:
https://asecuritysite.com/encryption/openpgp

### C.3	
An important element in data loss prevention is encrypted emails. In this part of the lab we will use an open source standard: PGP.  


#### 1. Create a key pair with (RSA and 2,048-bit keys):

<pre>
gpg --gen-key
</pre>

Now export your public key using the form of:
```
gpg --export -a "Your name" > mypub.key
```
Now export your private key using the form of:
```
gpg --export-secret-key -a "Your name" > mypriv.key
```

How is the randomness generated?



Outline the contents of your key file:

#### 2. Now send your lab partner your public key in the contents of an email, and ask them to import it onto their key ring (if you are doing this on your own, create another set of keys to simulate another user, or use Bill’s public key – which is defined at http://asecuritysite.com/public.txt and send the email to him):
```
gpg --import theirpublickey.key
```

Now list your keys with:
```
gpg --list-keys
```

Which keys are stored on your key ring and what details do they have:




#### 3. Create a text file, and save it. Next encrypt the file with their public key:
```
gpg -e -a -u "Your Name" -r "Your Lab Partner Name" hello.txt
```

What does the –a option do:


What does the –r option do:


What does the –u option do:


Which file does it produce and outline the format of its contents:


#### 4. Send your encrypted file in an email to your lab partner, and get one back from them.

Now create a file (such as myfile.asc) and decrypt the email using the public key received from them with:
```
gpg –d myfile.asc > myfile.txt
```

Can you decrypt the message:

#### 5. Next using this public key file, send Bill (w.buchanan@napier.ac.uk) a question (http://asecuritysite.com/public.txt):

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
nucbcNB98DkLlND905oV
=XVeB
-----END PGP PUBLIC KEY BLOCK-----	
```


Did you receive a reply:

#### 6. Next send your public key to Bill (w.buchanan@napier.ac.uk), and ask for an encrypted message from him.
	



## D GitHub Keys

### I.1
On your machine, go into the ~/.ssh folder. Now generate your SSH keys:

```
ssh-keygen -t rsa -C "your email address"
```

The public key should look like this:

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLrriuNYTyWuC1IW7H6yea3hMV+rm029m2f6IddtlImHrOXjNwYyt4Elkkc7AzOy899C3gpx0kJK45k/CLbPnrHvkLvtQ0AbzWEQpOKxI+tW06PcqJNmTB8ITRLqIFQ++ZanjHWMw2Odew/514y1dQ8dccCOuzeGhL2Lq9dtfhSxx+1cBLcyoSh/lQcs1HpXtpwU8JMxWJl409RQOVn3gOusp/P/0R8mz/RWkmsFsyDRLgQK+xtQxbpbodpnz5lIOPWn5LnT0si7eHmL3WikTyg+QLZ3D3m44NCeNb+bOJbfaQ2ZB+lv8C3OxylxSp2sxzPZMbrZWqGSLPjgDiFIBL w.buchanan@napier.ac.uk
```

View the private key. What is the DEK-Info part, and how would it be used to protect the key, and what information does it contain?


On your Ubuntu instance setup your new keys for ssh:

```
ssh-add ~/.ssh/id_git
```

Now create a Github account and upload your public key to Github (select Settings-> New SSH key or Add SSH key).  Create a new repository on your GitHub site, and add a new file to it. Next go to your Ubuntu instance and see if you can clone of a new directory:

git clone ssh://git@github.com/<user>/<repository name>.git

If this doesn’t work, try the https connection that is defined on GitHub.



