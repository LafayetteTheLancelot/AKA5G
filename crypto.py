import os
import itertools
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import datetime
import time


def getKey(macFailure = False):
    if macFailure:
        return os.urandom(256)
    return b'\xff\xdd\xb4\xc0\tzFs4\x83\xc5\x83\x86\xb9d\xe9]\x86\xd42\xbai\xf2Z2\xde\xd5\xf6\x82\x17\xed\xc2\x06D\x15\xf1\x01u\xf2\x03z\xa9\xbe\xf3\x0cA\x94;.\xdb\x1e/\x02.\x9c{\xc3\x9f&0\x1d\x8d\xeb\x0f(\xbdS\x0f}\rC\x93r\xfd\x94\xa8BQ#\x87\xff\xaa\xa3\xe7P\xa9\xfb\xa6\'\x93\xbc\xdb\x98.\xec\x0b\xce\x16V\xf1\x82\xc6w\xe2\xc0\xb5\xa7\xefh\x86\xbcO\xf7\x89\xaaT\xac\x1e\xfa\x8c`U\xa9\x82y\x8f\xa6\xed{\xf8\x16\x8f\xb2\x9d\xde<\xdb\x91\x91\xd0\x80Q\xd1dX@\xdd\xe2\xfcv#\xea5\xaeod\xba\xdei\xac:\x11yk\xeb\xe0=V\xe2@3\x02/=-l\xa3\xfa\xd2\xe2\x7f\x05\x18\xd0\xe8\xa6\xfc\x1f\xc7\xbct\x19\x0f\xc3\xb7_\x0b\xef\xa2.\x95\x06o\x04/\xd9\x9b\xd1\x891\\\x9c\xbd:\x1cJ+\to\xc8\x19\x9d\x19\x88m\x86\xbc\xd46\x03\xc1\x83\xae\x13a\x98;\x137v\x11\xcfY\xe8\xa5\xfdt"\xe8OF;\x05v<@'

def getRandom(n):
    return os.urandom(n)

def fun1(k, sqn_hn, r):
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(k)
    bsqn_hn = sqn_hn.to_bytes(256, byteorder='little')
    digest.update(bsqn_hn)
    digest.update(r)
    return digest.finalize()

def fun5(k, r):
    digest = hashes.Hash(hashes.SHAKE256(256))
    digest.update(k)
    digest.update(r)
    return digest.finalize()

def getXOR(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def challenge(k, r, sname):
    salt = getXOR(k, r)
    # derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=256,
        salt=salt,
        iterations=480000,
    )
    bsname = sname.encode()
    return kdf.derive(bsname)

def getsha256(r, res):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(r)
    digest.update(res)
    return digest.finalize()

def keySeed(k, r, sqn_hn, sname):
    bsqn_hn = sqn_hn.to_bytes(256, byteorder='little')
    salt = getXOR(bsqn_hn, getXOR(k, r))
    # derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=256,
        salt=salt,
        iterations=480000,
    )
    bsname = sname.encode()
    return kdf.derive(bsname)

def fun1_star(k, sqn_hn, r):
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(k)
    bsqn_hn = sqn_hn.to_bytes(256, byteorder='little')
    digest.update(bsqn_hn)
    digest.update(r)
    return digest.finalize()

def fun5_star(k, r):
    digest = hashes.Hash(hashes.SHAKE256(256))
    digest.update(k)
    digest.update(r)
    return digest.finalize()