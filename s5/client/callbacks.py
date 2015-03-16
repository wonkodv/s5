"""
    Callbacks for the client when information is needed, the user has to decide
    something. Collection of all callbacks in all Client-Mixins
"""

from pathlib import Path
import re
import configparser

class Callbacks():

    """ All possible callbacks needed by any MixIn, all raise not implemented
    error. """

    def getDataDirectory(self):
        """ The Directory where the S5Client stores data """
        raise NotImplementedError()

    def getConnectionTimeout(self):
        """ Timeout for tcp connections in sec (float)"""
        raise NotImplementedError()

    def getConnectionCipherSuites(self):
        """ Get a list of cipher suite names the client accepts. """
        raise NotImplementedError()

    def getNewItemHashMethod(self):
        """ For new Items: the HashMethod"""
        raise NotImplementedError()

    def getNewItemEncryptionMethod(self):
        """ The Symmetric Encryption Method for new Items"""
        raise NotImplementedError()

    def getNewItemCompressionMethod(self):
        """ For new Items: the method to compress the content before
        encryption"""
        raise NotImplementedError()

    def askForUserKeyPassword():
        """ The password to decrypt the user key """
        raise NotImplementedError()

    def askForNewUserKeyPassword(self):
        """ The password to use for a newly created devie key (e.g. enter
        twice) """
        raise NotImplementedError()

    def getNewUserKeyAlgorithm(self):
        """ The Asymmetric Encryption Algorithm of the new user key """
        raise NotImplementedError()

    def getNewUserKeyProtectionAlgorithm(self):
        """ The Symmetric Encryption Algorithm to stroe the new user
        key on disk encrypted"""
        raise NotImplementedError()

    def getNewUserKeyProtectionPBKDF(self):
        """ The Method to derive a key from a password for encrypting the new
        user
        key on disk encrypted"""
        raise NotImplementedError()

    def getUserKeyExportPasswordLength(self):
        """ The length of the password, generated when exporting a user private
        key"""
        raise NotImplementedError()

    def askForPasswordToImportUserKey(self):
        """ The password to import an exported key """
        raise NotImplementedError()

    def getNewServerAsymmetricKeyFingerprintMethod(self):
        """ The HashMethod to hash a servers public key """
        raise NotImplementedError()

    def verifyNewServerFingerprint(self, fp, fpm):
        """ ask the user if the fingerprint is ok, return true, false or throw
        favorite exception """
        raise NotImplementedError()

    def getNewSyncVersioningScheme(self, itemId, server):
        """ First sync of item to Server: the vewrsioning scheme, the server
        should use """
        raise NotImplementedError()

    def getNewShareEncryptionAlgorithm(self):
        """ When a user creates a new Share on the Server,
            use this symmetric Encryption Algorithm to encrypt the itemKeys
        """
        raise NotImplementedError()

    def getNewShareMACAlgorithm(self):
        """ When a user creates a new Share on the Server,
            use this Message Authentication Method to ensure that (userid ->
            userpublicKey) was written by someone who already has read access
            to the shareKey
        """
        raise NotImplementedError()

    def getNewShareFingerprintMethod(self):
        """ how fingerprints are made from keys """
        raise NotImplementedError()

    def getNewShareTemporaryAsymmetricKeyAlgo(self):
        """ The Algorithm for temporary Keys used to share with someone"""
        raise NotImplementedError()

    def getNewShareTemporaryKeyProtectionMethod(self):
        """ When a new Temporary Key is created for sharing, encrypt that with
        this method"""
        raise NotImplementedError()

    def getNewShareTemporaryKeyProtectionPBKDF(self):
        """ When a new Temporary Key is created for sharing, encrypt that with
        a key, derived from a password using this method"""
        raise NotImplementedError()

    def getNewShareTemporaryKeyPasswordLength(self):
        """ When a new Temporary Key is created for sharing, encrypt that with
        a password. Generate a password with this length. """
        raise NotImplementedError()

    def getEmailToUseInShares(self):
        """ When creating or modifying share groups, set this as email address"""
        raise NotImplementedError()

    def __getattr__(self, attr):
        """ Raise error here, since all callback methods should have a NIE-stub
        here."""
        raise AttributeError(attr)

class TestCallbacks(Callbacks):

    """ Callbacks to test the client classes return the attribute previously
            set """

    password = "Password"
    ciphersuites = ['HASHEDRANDOM-sha1-WITH-aes-128-cbc-pkcs7pad']
    symEncryption = 'aes-128-cbc-pkcs7pad'
    asymEncryption = 'rsa-1024-oaep-sha1'
    pbkdf = 'pbkdf2-1k-hmac-sha1'
    hashMethod = 'sha1'
    compression = 'zlib-1'
    mac = 'hmac-sha1'
    timeout = 0.2
    versioningScheme = 'last(10)'
    passwordLength=10

    def askForUserKeyPassword(self):
        return self.password

    def askForNewUserKeyPassword(self):
        return self.password

    def getConnectionCipherSuites(self):
        return self.ciphersuites

    def getNewUserKeyAlgorithm(self):
        return self.asymEncryption

    def getNewUserKeyProtectionAlgorithm(self):
        return self.symEncryption

    def getNewUserKeyProtectionPBKDF(self):
        return self.pbkdf

    def getNewItemHashMethod(self):
        return self.hashMethod

    def getNewItemEncryptionMethod(self):
        return self.symEncryption

    def getNewItemCompressionMethod(self):
        return self.compression

    def getDataDirectory(self):
        return self.dataDir

    def verifyNewServerFingerprint(self, fp, fpm):
        return fp == self.expectedFingerprint

    def getVersioningSchemeForItem(self, itemId):
        return self.versioningScheme

    def getNewShareEncryptionAlgorithm(self):
        return self.symEncryption

    def getNewShareMACAlgorithm(self):
        return self.mac

    def getNewShareFingerprintMethod(self):
        return self.hashMethod

    def getNewShareTemporaryAsymmetricKeyAlgo(self):
        return self.asymEncryption

    def getNewShareTemporaryKeyProtectionMethod(self):
        return self.symEncryption

    def getNewShareTemporaryKeyProtectionPBKDF(self):
        return self.pbkdf

    def getEmailToUseInShares(self):
        return self.userEmail

    def getNewServerAsymmetricKeyFingerprintMethod(self):
        return self.hashMethod

    def getConnectionTimeout(self):
        return self.timeout

    def getNewSyncVersioningScheme(self, itemId, server):
        return self.versioningScheme

    def getUserKeyExportPasswordLength(self):
        return self.passwordLength

    def askForPasswordToImportUserKey(self):
        return self.importKeyPassword



class ConfigCallbacks(Callbacks):

    """ A callback that reads configurations from a config file in the data
    directory, with defaults from s5/client/default.ini """

    def __init__(self, dataDir):
        config = configparser.ConfigParser(interpolation=None)

        cfg = Path(__file__).parent / 'default.ini'
        with cfg.open('rt') as f:
            config.read_file(f)

        cfg = dataDir / 'config.ini'
        try:
            f = cfg.open('rt')
        except FileNotFoundError:
            pass
        else:
            with f:
                config.read_file(f)

        self.dataDir = dataDir
        self.config = config

    def _get(self, section, option):
        try:
            return self.config.get(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            raise KeyError(section, option)

    def getDataDirectory(self):
        return self.dataDir

    def getConnectionTimeout(self):
        return int(self._get('Network','Timeout'))

    def getConnectionCipherSuites(self):
        s = self._get('Network','Cipher Suites')
        l = re.split('[,\s]+',s)
        return [ s for s in l if len(s) > 0 ]

    def getNewItemHashMethod(self):
        return self._get('Item','Hash Method')

    def getNewItemEncryptionMethod(self):
        return self._get('Item','Encryption Method')

    def getNewItemCompressionMethod(self):
        return self._get('Item','Compression Method')

    def getNewUserKeyAlgorithm(self):
        return self._get('User Key','Algorithm')

    def getNewUserKeyProtectionAlgorithm(self):
        return self._get('User Key','Password Encryption Method')

    def getNewUserKeyProtectionPBKDF(self):
        return self._get('User Key','Password Key Derivation')

    def getUserKeyExportPasswordLength(self):
        return int(self._get('User Key','Export Password Length'))

    def getNewServerAsymmetricKeyFingerprintMethod(self):
        return self._get('Server','Fingerprint Method')

    def getNewSyncVersioningScheme(self, itemId, server):
        try:
            vs = self._get('Server %s'%(server, ),'Versioning Scheme')
        except KeyError:
            vs = self._get('Server','Versioning Scheme')
        return vs

    def getNewShareEncryptionAlgorithm(self):
        return self._get('Share','Encryption Method')

    def getNewShareMACAlgorithm(self):
        return self._get('Share','MAC Method')

    def getNewShareFingerprintMethod(self):
        return self._get('Share','Fingerprint Method')

    def getNewShareTemporaryAsymmetricKeyAlgo(self):
        return self._get('Share','Temporary Key Algorithm')

    def getNewShareTemporaryKeyProtectionMethod(self):
        return self._get('Share','Password Encryption Method')

    def getNewShareTemporaryKeyProtectionPBKDF(self):
        return self._get('Share','Password Key Derivation')

    def getNewShareTemporaryKeyPasswordLength(self):
        return int(self._get('Share','Password Length'))

    def getEmailToUseInShares(self):
        return self._get('User','Email')
