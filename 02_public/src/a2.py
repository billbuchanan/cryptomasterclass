from Crypto.Util.number import *
from Crypto import Random
import Crypto
import gmpy2
import sys

bits=60
msg="Hello"

if (len(sys.argv)>1):
        msg=str(sys.argv[1])
if (len(sys.argv)>2):
        bits=int(sys.argv[2])

p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

n = p*q
PHI=(p-1)*(q-1)

e=65537
d=(gmpy2.invert(e, PHI))

m=  bytes_to_long(msg.encode('utf-8'))

c=pow(m,e, n)
res=pow(c,d ,n)

print "Message=%s\np=%s\nq=%s\n\nd=%d\ne=%d\nN=%s\n\nPrivate key (d,n)\nPublic key (e,n)\n\ncipher=%s\ndecipher=%s" % (msg,p,q,d,e,n,c,(long_to_bytes(res)))

