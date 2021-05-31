<!-- ![esecurity](https://raw.githubusercontent.com/billbuchanan/esecurity/master/z_associated/esecurity_graphics.jpg) -->

# Lab 4: Asymmetric (Public) Key
Objective: The key objective of this lab is to provide a practical introduction to public key encryption, and with a focus on RSA and Elliptic Curve methods. This includes the creation of key pairs and in the signing process.

Video demo: https://youtu.be/6T9bFA2nl3c 

Note: If you are using Python 3, instead of "pip install pycrypto" you can install pycryptodome with "pip3 install pycryptodome".

## A	RSA Encryption


### A.2	
Bob has a private RSA key of:
```
-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDoIhiWs15X/6xiLAVcBzpgvnuvMzHBJk58wOWrdfyEAcTY10oG\n+6auNFGqQHYHbfKaZlEi4prAoe01S/R6jpx8ZqJUN0WKNn5G9nmjJha9Pag28ftD\nrsT+4LktaQrxdNdrusP+qI0NiYbNBH6qvCrK0aGiucextehnuoqgDcqmRwIDAQAB\nAoGAZCaJu0MJ2ieJxRU+/rRzoFeuXylUNwQC6toCfNY7quxkdDV2T8r038Xc0fpb\nsdrix3CLYuSnZaK3B76MbO/oXQVBjDQZ7jVQ5K41nVCEZOtRDBeX5Ue6CBs4iNmC\n+QyWx+u4OZPURq61YG7D+F1aWRvczdEZgKHPXl/+s5pIvAkCQQDw4V6px/+DJuZV\n5Eg20OZe0m9Lvaq+G9UX2xTA2AUuH8Z79e+SCus6fMVl+Sf/W3y3uXp8B662bXhz\nyheH67aDAkEA9rQrvmFj65n/D6eH4JAT4OP/+icQNgLYDW+u1Y+MdmD6A0YjehW3\nsuT9JH0rvEBET959kP0xCx+iFEjl81tl7QJBAMcp4GZK2eXrxOjhnh/Mq51dKu6Z\n/NHBG3jlCIzGT8oqNaeK2jGLW6D5RxGgZ8TINR+HeVGR3JAzhTNftgMJDtcCQQC3\nIqReXVmZaeXnrwu07f9zsI0zG5BzJ8VOpBt7OWah8fdmOsjXNgv55vbsAWdYBbUw\nPQ+lc+7WPRNKT5sz/iM5AkEAi9Is+fgNy4q68nxPl1rBQUV3Bg3S7k7oCJ4+ju4W\nNXCCvRjQhpNVhlor7y4FC2p3thje9xox6QiwNr/5siyccw==\n-----END RSA PRIVATE KEY-----
```

And receives a ciphertext message of:

```
uW6FQth0pKaWc3haoqxbjIA7q2rF+G0Kx3z9ZDPZGU3NmBfzpD9ByU1ZBtbgKC8ATVZzwj15AeteOnbjO3EHQC4A5Nu0xKTWpqpngYRGGmzMGtblW3wBlNQYovDsRUGt+cJK7RD0PKn6PMNqK5EQKCD6394K/gasQ9zA6fKn3f0=
```

Using the following code:

```python
# https://asecuritysite.com/encryption/rsa_example
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

binPrivKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDoIhiWs15X/6xiLAVcBzpgvnuvMzHBJk58wOWrdfyEAcTY10oG\n+6auNFGqQHYHbfKaZlEi4prAoe01S/R6jpx8ZqJUN0WKNn5G9nmjJha9Pag28ftD\nrsT+4LktaQrxdNdrusP+qI0NiYbNBH6qvCrK0aGiucextehnuoqgDcqmRwIDAQAB\nAoGAZCaJu0MJ2ieJxRU+/rRzoFeuXylUNwQC6toCfNY7quxkdDV2T8r038Xc0fpb\nsdrix3CLYuSnZaK3B76MbO/oXQVBjDQZ7jVQ5K41nVCEZOtRDBeX5Ue6CBs4iNmC\n+QyWx+u4OZPURq61YG7D+F1aWRvczdEZgKHPXl/+s5pIvAkCQQDw4V6px/+DJuZV\n5Eg20OZe0m9Lvaq+G9UX2xTA2AUuH8Z79e+SCus6fMVl+Sf/W3y3uXp8B662bXhz\nyheH67aDAkEA9rQrvmFj65n/D6eH4JAT4OP/+icQNgLYDW+u1Y+MdmD6A0YjehW3\nsuT9JH0rvEBET959kP0xCx+iFEjl81tl7QJBAMcp4GZK2eXrxOjhnh/Mq51dKu6Z\n/NHBG3jlCIzGT8oqNaeK2jGLW6D5RxGgZ8TINR+HeVGR3JAzhTNftgMJDtcCQQC3\nIqReXVmZaeXnrwu07f9zsI0zG5BzJ8VOpBt7OWah8fdmOsjXNgv55vbsAWdYBbUw\nPQ+lc+7WPRNKT5sz/iM5AkEAi9Is+fgNy4q68nxPl1rBQUV3Bg3S7k7oCJ4+ju4W\nNXCCvRjQhpNVhlor7y4FC2p3thje9xox6QiwNr/5siyccw==\n-----END RSA PRIVATE KEY-----"

ciphertext=base64.b64decode("uW6FQth0pKaWc3haoqxbjIA7q2rF+G0Kx3z9ZDPZGU3NmBfzpD9ByU1ZBtbgKC8ATVZzwj15AeteOnbjO3EHQC4A5Nu0xKTWpqpngYRGGmzMGtblW3wBlNQYovDsRUGt+cJK7RD0PKn6PMNqK5EQKCD6394K/gasQ9zA6fKn3f0=")

privKeyObj = RSA.importKey(binPrivKey)
cipher = PKCS1_OAEP.new(privKeyObj)
message = cipher.decrypt(ciphertext)

print
print ("====Decrypted===")
print ("Message:",message)
```


What is the plaintext message that Bob has been sent?




 

## D	Elliptic Curve Encryption
### D.1	
In the following Bob and Alice create elliptic curve key pairs. Bob can encrypt a message for Alice with her public key, and she can decrypt with her private key. Copy and paste the program from here:

https://asecuritysite.com/encryption/elc

Code used:

```python
import OpenSSL
import pyelliptic

secretkey="password"
test="Test123"

alice = pyelliptic.ECC() 
bob = pyelliptic.ECC()

print ("++++Keys++++")
print ("Bob's private key: ",bob.get_privkey().hex())
print ("Bob's public key: ",bob.get_pubkey().hex())

print()
print ("Alice's private key: ",alice.get_privkey().hex())
print ("Alice's public key: ",alice.get_pubkey().hex())


ciphertext = alice.encrypt(test, bob.get_pubkey())

print ("\n++++Encryption++++")

print ("Cipher: "+ciphertext.hex())

print ("Decrypt: "+bob.decrypt(ciphertext))
```

For a message of “Hello. Alice”, what is the ciphertext sent (just include the first four characters):



### D.2 	
Let’s say we create an elliptic curve with y<sup>2</sup> = x<sup>3</sup> + 7, and with a prime number of 89, generate the first five (x,y) points for the finite field elliptic curve. You can use the Python code at the following to generate them:

https://asecuritysite.com/encryption/ecc_points

First five points:







## E	RSA
### E.1 
A simple RSA program to encrypt and decrypt with RSA is given next. Prove its operation:
```

import rsa
(bob_pub, bob_priv) = rsa.newkeys(512)

msg='Here is my message'
ciphertext = rsa.encrypt(msg.encode(), bob_pub)
message = rsa.decrypt(ciphertext, bob_priv)
print(message.decode('utf8'))
```

Now add the lines following lines after the creation of the keys:

```
print (bob_pub)
print (bob_priv)
```


Can you identify what each of the elements of the public key (e,N), the private key (d,N), and the two prime number (p and q) are (if the numbers are long, just add the first few numbers of the value):




When you identity the two prime numbers (p and q), with Python, can you prove that when they are multiplied together they result in the modulus value (N):

Proven Yes/No




### E.2	
We will follow a basic RSA process. If you are struggling here, have a look at the following page:

https://asecuritysite.com/encryption/rsa

First, pick two prime numbers:

p=

q=

Now calculate N (p.q) and PHI [(p-1).(q-1)]:

N=

PHI = 

Now pick a value of e which does not share a factor with PHI [gcd(PHI,e)=1]:

e=

Now select a value of d, so that (e.d) (mod PHI) = 1:

[Note: You can use this page to find d: https://asecuritysite.com/encryption/inversemod]

d=

Now for a message of M=5, calculate the cipher as:

C = M<sup>e</sup> (mod N) = 

Now decrypt your ciphertext with:

M = C<sup>d</sup> (mod N) =

Did you get the value of your message back (M=5)? If not, you have made a mistake, so go back and check.

Now run the following code and prove that the decrypted cipher is the same as the message: 

```python
import libnum

p=11
q=3
N=p*q
PHI=(p-1)*(q-1)
e=3

d= libnum.invmod(e,PHI)

print (e,N)
print (d,N)
M=4
print ("\nMessage:",M)
cipher = M**e % N
print ("Cipher:",cipher)
message = cipher**d % N
print ("Message:",message)
```


Select three more examples with different values of p and q, and then select e in order to make sure that the cipher will work:




### E.2	
In the RSA method, we have a value of e, and then determine d from (d.e) (mod PHI)=1. But how do we use code to determine d? Well we can use the Euclidean algorithm. The code for this is given at:

https://asecuritysite.com/encryption/inversemod

Using the code, can you determine the following:

```
Inverse of 53 (mod 120) = 
Inverse of 65537 (mod 1034776851837418226012406113933120080) = 
```

Using this code, can you now create an RSA program where the user enters the values of p, q, and e, and the program determines (e,N) and (d,N)?


### E.3	
Run the following code and observe the output of the keys. If you now change the key generation key from ‘PEM’ to ‘DER’, how does the output change:





```python
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

binPrivKey = key.exportKey('PEM')
binPubKey =  key.publickey().exportKey('PEM')

print (binPrivKey)
print (binPubKey)
```


### E.4	
A simple RSA program to encrypt and decrypt with RSA is given next. Prove its operation:
```python
import rsa
(bob_pub, bob_priv) = rsa.newkeys(512)
ciphertext = rsa.encrypt('Here is my message'.encode(), bob_pub)
message = rsa.decrypt(ciphertext, bob_priv)
print(message.decode('utf8'))
```
A sample [here](https://repl.it/@billbuchanan/rsanew01#main.py)

## F	PGP
### F.1	
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

### F.2	
Using the code at the following link, generate a key:
https://asecuritysite.com/encryption/openpgp

### F.3	
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
	



## G GitHub Keys

### I.1
On your VM, go into the ~/.ssh folder. Now generate your SSH keys:

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




## H	What I should have learnt from this lab?
The key things learnt:

* The basics of the RSA method.
* The process of generating RSA and Elliptic Curve key pairs.
* To illustrate how the private key is used to sign data, and then using the public key to verify the signature.

A reflective statement:

* In ECC, we use a 256-bit private key. This is used to generate the key for signing Bitcoin transactions. Do you think that a 256-bit key is largest enough? If we use a cracker what performs 1 Tera keys per second, will someone be able to determine our private key?

## Additional
The following is code which performs RSA key generation, and the encryption and decryption of a message (https://asecuritysite.com/encryption/rsa_example):

```python
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from base64 import b64encode
from Crypto.Cipher import PKCS1_OAEP
import sys

msg = "hello..."

if (len(sys.argv)>1):
        msg=str(sys.argv[1])

key = RSA.generate(1024)

binPrivKey = key.exportKey('PEM')
binPubKey =  key.publickey().exportKey('PEM')

print
print ("====Private key===")
print (binPrivKey)
print
print ("====Public key===")
print (binPubKey)

privKeyObj = RSA.importKey(binPrivKey)
pubKeyObj =  RSA.importKey(binPubKey)


cipher = PKCS1_OAEP.new(pubKeyObj)
ciphertext = cipher.encrypt(msg.encode())

print
print ("====Ciphertext===")
print (b64encode(ciphertext))

cipher = PKCS1_OAEP.new(privKeyObj)
message = cipher.decrypt(ciphertext)


print
print ("====Decrypted===")
print ("Message:",message)
```

The code is [here](https://repl.it/@billbuchanan/rsanewcode#main.py). Can you decrypt this:

```
fIVuuWFLVANs9MjatXbIbtH7/n0dBpDirXKi82jZovXS/krxy43cP0J9jlNz4dqxLgdiqtRe1AcymX06JUo1SrcqDEh3lQxoU1KUvV7jG9GE3pSxHq4dQlcWdHz95b9go6QYbe/5S/uJgolR+S9qaDE8tXYysP8FeXIPd0dXxHo=
```

The private key is:

```
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCfQfirYVXgzT90v6SqgeID7q/WK1XaVTNGVFolDUOcrXl/egRG
4iag5tiTbrMYCQ8CSTYn7q0U4AmBXihlbWDqf6MMk6OEoDxdWZTiG1MmQ1wZikFE
s7sYSog/poYleCeYW8kVzHNWnt9IuQWekIg6ZHkwp4NE/aW8HxvEwYRqCQIDAQAB
AoGAE6rkiFmxbt06GHNwZQQ8QssP2Q2qARgjiGxzY38DWg6MYiNR8uUL6zQHDBIQ
OQgpW9lpwD24D0tpsRnNOFVtMeafcxmykX+qHGtNeKJuTtqSm2eTI6gNbC8iosGT
XJEPM8tc/dfZ2sDobLfi0alWFOzWo8vKaLnnAdMHoZ8mDo8CQQDCMx08JVlTW1zl
+4UTEnyyYmIezw5ORfMqPtN1LpQ4ptYnHNMVJPWcpRwBYZfHlPOPtuVwo6gzv82G
QpgQsd4PAkEA0fA8e8R6JbeUR1HxsqWeCnPz3Ahq5Ya5WA6HyJQml9aDVqKDDp2L
3AcqsvFEKJ/T34r31so2yW6hj2yFBnzOZwJBAIqanrgJ1CpJYBGJJd6J6FQNIgjp
MUWuaTJyqsvNFd8lPF2oFgPWYDKQKV/W/tRkvD2LhVCSjf95WsADkbMAsAMCQAHo
wWQOwV2eccbERAJv5yQJMeqKWQ6FTyIx36I/VqqC1Obwy2hSnnb9ybGe6BPGgFLE
HMTjSeRDEU0Qm5UXhXkCQQCPlZJqlgksBN/TULHC4RgsXIx+oFylBrkiFamYsuEt
Kn52h41pX7FI5TXcqIDPw+uqAu50JnwDR0dLYY6fvIce
-----END RSA PRIVATE KEY-----
```




