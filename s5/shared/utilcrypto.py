"""
    Collection of helpers to use cryptographic primitives
"""

import logging
from . import serialize
from . import crypto


def hashFile(algo, path):
    h = crypto.getHashAlgorithm(algo)
    blocksize = 2 ** 20
    with path.open('rb') as f:
        d = f.read(blocksize)
        while d:
            h.update(d)
            d = f.read(blocksize)
    return h.hexdigest()


def fileHashEqual(algo, path, compare):
    return hashFile(algo, path) == compare.lower()


def hashString(algo, string):
    h = crypto.getHashAlgorithm(algo)
    h.update(string.encode())
    return h.hexdigest()


def authenticateMessage(macAlgo, key, message):
    mac = crypto.getMACAlgorithm(macAlgo)
    mac = mac(key)
    mac.update(message)
    return mac.hexdigest()


def getFingerprintFromAsymmetricKey(key, method):
    assert key['type'] == 'public'
    h = crypto.getHashAlgorithm(method)
    for k in sorted(key.keys()):
        s = str(key[k])
        b = serialize.strToBytes(s)
        h.update(b)
    return h.hexdigest()


def encryptSymmetric(algorithm, key, plainData):
    sAlg = crypto.getSymmetricEncryptionAlgorithm(algorithm)
    iv = sAlg.getIV()
    enc = sAlg.getEncryptor(key, iv)
    enc.putPlain(plainData)
    enc.finish()
    b = b''
    while enc.hasMore():
        b = b + enc.getEncrypted()

    return b, iv


def decryptSymmetric(algorithm, key, iv, encryptedData):
    sAlg = crypto.getSymmetricEncryptionAlgorithm(algorithm)
    dec = sAlg.getDecryptor(key, iv)
    dec.putEncrypted(encryptedData)
    dec.finish()
    b = b''
    while dec.hasMore():
        b = b + dec.getDecrypted()

    return b


def decrypt_asymmetric(data, key):
    algo = key['algorithm']
    algo = crypto.getAsymmetricEncryptionAlgorithm(algo)
    dec = algo.getDecryptor(key)
    return dec.decrypt(data)


def encrypt_asymmetric(data, key):
    algo = key['algorithm']
    algo = crypto.getAsymmetricEncryptionAlgorithm(algo)
    enc = algo.getEncryptor(key)
    return enc.encrypt(data)


def passwordProtectData(data, password, algo, pbkdf, returnAsBytes=True):
    """ encrypt data with a password
        * data: bytes
        * password: str
        * algo:str the encryption algorithm (e.g. aes-128-cbc-pkcs7pad)
        * pbkdf:str the passwordToKey function (e.g. pbkdf2-1000-hmac-sha1)
        return bytes that contain all parameters neccessary for decryption
    """
    wrap = {}
    impl = crypto.getSymmetricEncryptionAlgorithm(algo)
    salt = crypto.getRandomBytes(impl.getKeySize())  # DECISION !

    kdf = crypto.getPBKDFAlgorithm(pbkdf)
    skey = kdf(password, salt, impl.getKeySize())
    data, iv = encryptSymmetric(algorithm=algo, key=skey, plainData=data)

    wrap['algorithm'] = algo
    wrap['pbkdf'] = pbkdf
    if iv is not None:
        wrap['iv'] = serialize.base64encode(iv)
    wrap['salt'] = serialize.base64encode(salt)
    data = serialize.base64encode(data)
    wrap['data'] = data
    if returnAsBytes:
        return serialize.objToBytes(wrap)
    else:
        return wrap


def extractPasswordProtectedData(wrap, password):
    """ decrypt data, protected with passwordProtectData()
        * wrap: bytes or dict, the output of passwordProtectData()
        * password: str
        return data as bytes
    """
    if isinstance(wrap, bytes):
        wrap = serialize.bytesToObj(wrap)
    data = wrap['data']
    data = serialize.base64decode(data)
    if 'iv' in wrap:
        iv = serialize.base64decode(wrap['iv'])
    else:
        iv = None
    salt = serialize.base64decode(wrap['salt'])
    impl = crypto.getSymmetricEncryptionAlgorithm(wrap['algorithm'])
    kdf = crypto.getPBKDFAlgorithm(wrap['pbkdf'])
    skey = kdf(password, salt, impl.getKeySize())
    data = decryptSymmetric(
        algorithm=wrap['algorithm'], key=skey, iv=iv, encryptedData=data)
    return data


def generatePassword(length):
    pwchars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnopqrstuvwxyz123456789+-@"
    l = len(pwchars)
    r = ""
    for i in range(length):
        x = crypto.getRandomInt(0, l - 1)
        r += pwchars[x]
    return r


crypto.Algorithms.ensureLoaded()
CIPHER_SUITES = {}
for c in crypto.Algorithms.symmetricEncryptionAlgos:
    for h in crypto.Algorithms.hashAlgos:
        s = 'HASHEDRANDOM-%s-WITH-%s' % (h.lower(), c.lower())
        CIPHER_SUITES[s] = (h, c)
