"""
    Client side Networking
"""

import time
import logging

from ..shared import crypto
from ..shared import utilcrypto
from ..shared import messaging
from ..shared import serialize
from ..shared.permissions import PermissionSet
from ..shared.util import addAttribute

from ..shared.messaging import CorruptMessage, UnexpectedMessage

logger = logging.getLogger(__name__)

class AccessRestricted(Exception):
    pass


class ClientProtocol(messaging.S5BaseProtocol):

    """ Handles Clientside Communication with a server"""

    def __init__(self, socket):
        super().__init__(socket)
        self.isSetUp = False,

    def receiveMessage(self, *expectedTypes):
        """ receive Message """
        try:
            return super().receiveMessage(*expectedTypes)
        except UnexpectedMessage as e:
            m = e.message
            if m.TYPE == 'SError':
                code = m.getCode()
                msg = m.getMessage()
                if code == 'AccessRestricted':
                    raise AccessRestricted(msg) from None
            raise e

    def setup(self, userPublicKey, userPrivateKey, verifyServerKey,
              cipher_suites):
        """ All steps until a secured channel is established and requests can
        be sent
        """
        self.userPublicKey = userPublicKey

        # collect incoming and outgoing data to hash later.
        self.startCollecting()

        m = messaging.Message.CHello(
            ProtocolVersion=self.PROTOCOL_VERSION,
            CipherSuites=cipher_suites
        )
        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.SHello)
        serverKey = m.getServerPublicKey()

        if not verifyServerKey(serverKey):
            raise Exception("ServerKeyMissmatch")

        cs = m.getSelectedCipherSuite()

        # agree upon cipher suite, server choses
        if cs not in cipher_suites:
            raise CorruptMessage("Unknown CipherSuite ", cs)

        HASH_METHOD, ENCRYPTION_METHOD = utilcrypto.CIPHER_SUITES[cs]

        symmetric_algo = crypto.getSymmetricEncryptionAlgorithm(
            ENCRYPTION_METHOD)
        key_size = symmetric_algo.getKeySize()

        # Key Exchange
        # ------------
        #
        # Client generates Random Bytes, key_c
        # sends them encrypted to server,
        # receives encrypted random bytes from server
        # decrypts them
        #
        # x = hash(hash(key_c) + hash(key_s))
        # take client to server and server to client key from start of
        # Key Material = x + hash(x) + hash(hash(x)) + ...

        key_c = crypto.getRandomBytes(key_size)

        key_c_enc = utilcrypto.encrypt_asymmetric(key_c, serverKey)
        m = messaging.Message.KeyExchange(
                Step="HR-Client",
                Data=[serialize.base64encode(key_c_enc), userPublicKey]
                )
        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.KeyExchange)
        if not m.getStep() == "HR-Server":
            raise CorruptMessage("Expected KeyExchange Step HR-Server, not",
                                 m.getStep())
        key_s_enc = serialize.base64decode(m.getData())
        key_s = utilcrypto.decrypt_asymmetric(key_s_enc, userPrivateKey)

        def hash(data):
            h = crypto.getHashAlgorithm(HASH_METHOD)
            h.update(data)
            return h.digest()

        key_c = hash(key_c)
        key_s = hash(key_s)

        b = hash(key_c + key_s)
        key_material = b
        while len(key_material) < 2 * key_size:
            b = hash(b)
            key_material += b

        key_client_to_server = key_material[:key_size]
        key_server_to_client = key_material[key_size:2 * key_size]

        assert key_client_to_server != key_server_to_client
        assert len(key_client_to_server) == key_size
        assert len(key_server_to_client) == key_size

        iv = b'\x00' * symmetric_algo.getBlockSize()
        enc = symmetric_algo.getEncryptor(key_client_to_server, iv)
        dec = symmetric_algo.getDecryptor(key_server_to_client, iv)

        # stop collecting, Fill the hashers with collected data and start a
        # secured Connection

        in_data, out_data = self.stopCollecting()

        h = crypto.getHashAlgorithm(HASH_METHOD)
        h.update(in_data)
        in_hash = h.hexdigest()

        in_hasher = h

        h = crypto.getHashAlgorithm(HASH_METHOD)
        h.update(out_data)
        out_hash = h.hexdigest()

        out_hasher = h

        self.secureConnection(
            encryptor=enc,
            decryptor=dec,
            out_hasher=out_hasher,
            in_hasher=in_hasher)

        # This message, and all following frames are automatically integrity
        # checked using in_hasher and out_hasher by base Protocol
        m = messaging.Message.NegotiationVerification()
        self.sendMessage(m)

        # If this message arrives, a secure channel is established.
        m = self.receiveMessage(messaging.Message.NegotiationVerification)

    def ping(self):
        m = messaging.Message.Ping()
        start = time.time()
        self.sendMessage(m)
        self.receiveMessage(messaging.Message.Ping)
        stop = time.time()
        return (stop - start)*1000

    @addAttribute(
        "ItemsParam",
        messaging.Message.CRequestNewVersionsForItems.ItemsParam)
    def getNewVersionsForItems(self, items):
        m = messaging.Message.CRequestNewVersionsForItems(Items=items)
        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.SSendNewItemVersions)
        return m.getVersions()

    def getItemVersion(self, itemId, versionId):
        """ Get Metadata and Content from the Server for an item at version """
        m = messaging.Message.CRequestItemVersion(
            ItemId=itemId, VersionId=versionId)
        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.SSendItemVersion)
        if m.getItemId() != itemId or m.getVersionId() != versionId:
            raise CorruptMessage(
                'Content for %s/%s instead %s/%s' %
                (m.getItemId(), m.getVersionId(), itemId, versionId))

        contentIter, length = self.receiveBlobIter()

        if m.hasShareId():
            shareId = m.getShareId()
            if not m.hasEncryptedShareKey():
                raise CorruptMessage()
            if not m.hasItemKeyEncryptionMethod():
                raise CorruptMessage()
            if not m.hasItemKeyEncryptionIV():
                raise CorruptMessage()
            itemKeyEncryptionIV = m.getItemKeyEncryptionIV()
            encryptedShareKey = m.getEncryptedShareKey()
            itemKeyEncryptionMethod = m.getItemKeyEncryptionMethod()
        else:
            shareId = None
            itemKeyEncryptionIV = None
            encryptedShareKey = None
            itemKeyEncryptionMethod = None
            if m.hasEncryptedShareKey():
                raise CorruptMessage()
            if m.hasItemKeyEncryptionMethod():
                raise CorruptMessage()
            if m.hasItemKeyEncryptionIV():
                raise CorruptMessage()

        metaData = dict(
            itemId=m.getItemId(),
            hashMethod=m.getHashMethod(),
            encryptionMethod=m.getEncryptionMethod(),
            compressionMethod=m.getCompressionMethod(),
            contentEncryptionIV=m.getContentEncryptionIV(),
            encryptedContentType=m.getEncryptedContentType(),
            typeEncryptionIV=m.getTypeEncryptionIV(),
            encryptedContentHash=m.getEncryptedContentHash(),
            hashEncryptionIV=m.getHashEncryptionIV(),
            shareId=shareId,
            itemKeyEncryptionIV=itemKeyEncryptionIV,
            itemKeyEncryptionMethod=itemKeyEncryptionMethod,
            encryptedShareKey=encryptedShareKey,
            encryptedItemKey=m.getEncryptedItemKey(),
            sizeOfEncryptedContent=length
        )

        return metaData, contentIter

    def addItemVersion(
            self,
            itemId,
            encContIter,
            sizeOfEncryptedContent,
            shareId,
            oldVersionId,
            versioningScheme,
            itemKeyEncryptionIV,
            **data):
        mp = dict(
            ItemId=itemId,
            HashMethod=data['hashMethod'],
            EncryptionMethod=data['encryptionMethod'],
            CompressionMethod=data['compressionMethod'],

            ContentEncryptionIV=data['contentEncryptionIV'],

            EncryptedContentType=data['encryptedContentType'],
            TypeEncryptionIV=data['typeEncryptionIV'],

            EncryptedContentHash=data['encryptedContentHash'],
            HashEncryptionIV=data['hashEncryptionIV'],

            EncryptedItemKey=data['encryptedItemKey'],
        )
        if shareId is not None:
            mp['ShareId'] = shareId
            assert itemKeyEncryptionIV
            mp['ItemKeyEncryptionIV'] = itemKeyEncryptionIV

        if not oldVersionId is None:
            mp['OldVersionId'] = oldVersionId
        else:
            assert versioningScheme is not None
            mp['VersioningScheme'] = versioningScheme

        m = messaging.Message.CNewItemVersion(**mp)

        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.SReceivedItemVersion)
        if m.getItemId() != itemId:
            raise CorruptMessage()
        if not m.getAccept():
            return False, m.getOffendingVersionId()

        if m.getSendContent():
            self.sendBlobFromIter(
                dataIter=encContIter, size=sizeOfEncryptedContent)
            m = self.receiveMessage(messaging.Message.SReceivedItemVersion)
            if m.getItemId() != itemId:
                raise CorruptMessage()

        if m.getAccept():
            return True, m.getNewVersionId()
        else:
            return False, m.getOffendingVersionId()

    def createShare(self, name, encryptMethod, macMethod, fingerprintMethod):
        m = messaging.Message.CCreateShare(
            Name=name,
            EncryptionMethod=encryptMethod,
            ShareMemberAuthenticationMethod=macMethod,
            FingerprintMethod=fingerprintMethod
        )
        self.sendMessage(m)
        m = self.receiveMessage(messaging.Message.SNewShare)
        shareId = m.getShareId()
        return shareId

    def getShare(self, shareId, forMe=False):
        """ Get the Share group from the Server.
            Returns share, members, myrecord
            if forMe, members is none,
        """
        m = messaging.Message.CGetShare(
            ShareId=shareId,
            ForMe=forMe
        )

        self.sendMessage(m)
        m = self.receiveMessage(messaging.Message.SSendShare)

        if not m.getShareId() == shareId:
            raise CorruptMessage()

        share = dict(
            ShareId=m.getShareId(),
            Owner=m.getOwner(),
            Name=m.getName(),
            EncryptionMethod=m.getEncryptionMethod(),
            ShareMemberAuthenticationMethod=m.getShareMemberAuthenticationMethod(),
            FingerprintMethod=m.getFingerprintMethod())

        members = m.getMembers()

        def decodeRec(rec):
            """ base64Encoding inside list of dicts is not handled by the
                Message Class, therfore go through them """
            data = rec._asdict()
            data['EncryptedShareKey'] = serialize.base64decode(
                data['EncryptedShareKey'])
            data['Permissions'] = PermissionSet.fromMask(data['Permissions'])
            return data
        members = list(map(decodeRec, members))

        if forMe:
            if not len(members) == 1:
                raise CorruptMessage()
            member = members[0]
            return share, None, member
        else:
            for m in members:
                if m['UserPublicKey'] == self.userPublicKey:
                    break
            else:
                raise CorruptMessage("Can not find you in Members")
            # return a dict with common data, a list of dicts with memer data,
            # and especially my record
            return share, members, m

    def addShareMember(self, shareId, email, permissions, userPublicKey,
                       encShareKey, auth):
        m = messaging.Message.CAddShareMember(
            ShareId=shareId,
            Email=email,
            Permissions=permissions,
            UserPublicKey=userPublicKey,
            EncryptedShareKey=encShareKey,
            MemberAuthentication=auth
        )
        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.SShareUpdated)
        if not m.getShareId() == shareId:
            raise CorruptMessage()

    def updateShareMember(self, shareId, oldPubKey, email, permissions,
                          userPublicKey, encShareKey, auth):

        m = messaging.Message.CUpdateShareMember(
            ShareId=shareId,
            OldUserPublicKey=oldPubKey,
            Email=email,
            Permissions=permissions,
            UserPublicKey=userPublicKey,
            EncryptedShareKey=encShareKey,
            MemberAuthentication=auth
        )
        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.SShareUpdated)
        if not m.getShareId() == shareId:
            raise CorruptMessage()

    def queryShares(self, name=None):
        p = {}
        if name is not None:
            p = {'Name': name}
        m = messaging.Message.CQueryShares(**p)
        self.sendMessage(m)

        m = self.receiveMessage(messaging.Message.SQuerySharesResult)

        return m.getShareIds()

    def sendToken(self, token):
        m = messaging.Message.CSendToken(Token=token)
        self.sendMessage(m)
        m = self.receiveMessage(messaging.Message.SAcceptToken)
        return m.getAccept()

    def close(self):
        if self.isOpen():
            m = messaging.Message.Close()
            try:
                self.sendMessage(m)
            except Exception as e:
                logger.info("%s",e,exc_info=e)
                pass
            finally:
                super().close()
