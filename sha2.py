import charm.core.crypto.cryptobase
from charm.core.math.pairing import pairing,pc_element,ZR
from charm.core.math.integer import integer,int2Bytes
from charm.toolbox.conversion import Conversion
from charm.toolbox.bitstring import Bytes
import hashlib, base64
     
"""
Waters Hash technique: how to hash in standard model.
Default - len=8, bits=32 ==> 256-bits total (for SHA-256)
For SHA1, len=5 bits=32 ==> 160-bits total
"""
class Waters:
    """
    >>> from charm.toolbox.pairinggroup import *
    >>> from charm.toolbox.hash_module import Waters
    >>> group = PairingGroup("SS512")
    >>> waters = Waters(group, length=8, bits=32)
    >>> a = waters.hash("user@email.com")
    """
    def __init__(self, group, length=8, bits=32, hash_func='sha256'):
        self._group = group
        self._length = length
        self._bitsize = bits
        self.hash_function = hash_func
        self._hashObj = hashlib.new(self.hash_function)
        self.hashLen = len(self._hashObj.digest())

    def sha2(self, message):
        h = self._hashObj.copy()
        h.update(message)
        return Bytes(h.digest())    

