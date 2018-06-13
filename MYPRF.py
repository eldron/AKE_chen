from charm.toolbox.paddingschemes import PKCS7Padding
from charm.toolbox.securerandom import OpenSSLRand
from charm.core.crypto.cryptobase import MODE_CBC,AES,selectPRP
import json
import hmac
from base64 import b64encode, b64decode

class MYPRF(object):

    def __init__(self, key, alg = AES, mode = MODE_CBC):
        self._alg = alg
        self.key_len = 16
        self._block_size = 16
        self._mode = mode
        self._key = key[0:self.key_len] # expected to be bytes
        assert len(self._key) == self.key_len, "SymmetricCryptoAbstraction key too short"
        self._padding = PKCS7Padding()
        #print('MYPRF initialized')

    def _initCipher(self,IV = None):
        if IV == None :
            IV =  OpenSSLRand().getRandomBytes(self._block_size)
        self._IV = IV
        return selectPRP(self._alg,(self._key,self._mode,self._IV))

    # def __encode_decode(self,data,func):
    #     data['IV'] = func(data['IV'])
    #     data['CipherText'] = func(data['CipherText'])
    #     return data

    # #This code should be factored out into another class
    # #Because json is only defined over strings, we need to base64 encode the encrypted data
    # # and convert the base 64 byte array into a utf8 string
    # def _encode(self, data):
    #     return self.__encode_decode(data, lambda x: b64encode(x).decode('utf-8'))

    # def _decode(self, data):
    #     return self.__encode_decode(data, lambda x: b64decode(bytes(x, 'utf-8')))

    # def encrypt(self, message):
    #     #This should be removed when all crypto functions deal with bytes"
    #     if type(message) != bytes :
    #         message = bytes(message, "utf-8")
    #     ct = self._encrypt(message)
    #     #JSON strings cannot have binary data in them, so we must base64 encode cipher
    #     cte = json.dumps(self._encode(ct))
    #     return cte

    def _encrypt(self, message):
        #Because the IV cannot be set after instantiation, decrypt and encrypt
        # must operate on their own instances of the cipher
        
        # we fix the IV, make the encryption a PRF
        initial_vector = b'1'
        initial_vector = initial_vector * self._block_size
        cipher = self._initCipher(initial_vector)

        ct= {'ALG': self._alg,
            'MODE': self._mode,
            'IV': self._IV,
            'CipherText': cipher.encrypt(self._padding.encode(message))
            }
        return ct

    # def decrypt(self, cipherText):
    #     f = json.loads(cipherText)
    #     return self._decrypt(self._decode(f))

    # def _decrypt(self, cipherText):
    #     cipher = self._initCipher(cipherText['IV'])
    #     msg = cipher.decrypt(cipherText['CipherText'])
    #     return self._padding.decode(msg)