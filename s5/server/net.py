"""
    Provide the Serverside Networking.

    Client connections are accepted and handled in a thread. All incoming
    requests are delegated to a Handler (s5.server.server.ServerMessageHandler ).

    NetworkServer is the class exposed by this module.
    * needs a MessageHandlerFactory
    * creates a ClientConnectionHandlerFactory
        * passes it the MHF
    * creates a ThreadedTCPServer
        * passes it the CCHF
    ThreadedTCPServer Listens for incoming Connections
        * When a new connection is created:
            * uses CCHF to create a new ClientConnectionHandler

    ClientConnectionHandlerFactory creates new CCH with access to the MHF

    ClientConnectionHandler
    * gets created with an established tcp connection
    * has the MHF
        * creates a new MessageHandler
    * creates a ServerProtocol
        * gives it the MessageHandler
        * gives it the TCP Socket
        * calls SP.loop()

    ServerProtocol
    *   has the tcp socket
    *   has the MessageHandler
    *   loop():
        * receive message
        * decode it
        * let MessageHandler do the requested Work
        * encode the Results
        * send them to the client
        * wait for more

"""

from ..shared import permissions
import socket
import sys
import socketserver
import logging

from ..shared import messaging
from ..shared import utilcrypto
from ..shared import serialize
from ..shared import crypto
from ..shared import utilcrypto

from ..shared.messaging import CorruptMessage, UnexpectedMessage

logger = logging.getLogger(__name__)


class ClientError(Exception):

    """ The client did something wrong """
    pass


class AccessRestricted(ClientError):

    """ Client lacks Permissions """
    pass


class NetworkServer():

    """ Interface to the serverside Networking """

    def __init__(self, messageHandlerFactory, exceptionHandler):
        self.messageHandlerFactory = messageHandlerFactory
        self.exceptionHandler = exceptionHandler

    def setup(self, addr, port, ipv6=False):
        """ Create the ServerSocket etc. """
        if ipv6:
            ServerClass = ThreadedTCPServerV6
        else:
            ServerClass = ThreadedTCPServer

        self.server = ServerClass(
            addr,
            port,
            self.exceptionHandler,
            ClientConnectionHandler.newFactory(
                self.messageHandlerFactory))
        logger.debug("Setup Server at %r", addr)

    def serve(self):
        """ accept clients until shutdown() is called """
        addr = self.getAddress()
        logger.debug("Accepting Connections at: %r", addr)
        self.server.serve_forever()

    def shutdown(self):
        """ shut the server down """
        self.server.shutdown()

    def close(self):
        self.server.socket.close()

    def getAddress(self):
        """ get the addess info the server is listening at (only after setup)"""
        a = self.server.socket.getsockname()
        return a


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    """ TCP Server that starts a thread for every connection """

    def __init__(
            self,
            address,
            port,
            exceptionHandler,
            connectionHandlerFactory):
        self.exceptionHandler = exceptionHandler
        super().__init__((address, port), connectionHandlerFactory)

    def handle_error(self, socket, addr):
        e = sys.exc_info()[1]
        self.exceptionHandler(socket, addr, e)


class ThreadedTCPServerV6(ThreadedTCPServer):
    """ TCP Server that uses IPv6 """
    address_family = socket.AF_INET6


class ClientConnectionHandler(socketserver.BaseRequestHandler):

    """ runs in its own thread, gets created with an established TCP
    connection. Creates a ServerProtocol which handles the messaging."""

    @classmethod
    def newFactory(cls, messageHandlerFactory):
        """ return a Factory creating ConnectionHandlers that can create MessageHandlers"""
        def factory(*args, **kwargs):
            h = ClientConnectionHandler(messageHandlerFactory, *args, **kwargs)
            return h
        return factory

    def __init__(self, messageHandlerFactory, *args, **kwargs):
        self.messageHandlerFactory = messageHandlerFactory
        super().__init__(*args, **kwargs)

    def handle(self):
        """ called to work with the socket, delegates to ServerProtocol """
        logger.info("Client connected from %r", self.client_address)
        messageHandler = self.messageHandlerFactory(self.client_address)
        sp = ServerProtocol(self.request, messageHandler)
        try:
            sp.loop()
        except Exception as e:
            try:
                sp.close()
            except:
                pass
            logger.error("Error handling Client Connection from %s: %s",
                         self.client_address, e, exc_info=e)
            raise e
        else:
            logger.info("Client %r disconnected", self.client_address)
        finally:
            messageHandler.close()


class ServerProtocol(messaging.S5BaseProtocol):

    """ Handles all serverside Communication with a Client

    needs a messageHandler that performs the actual work"""
    logger = logging.getLogger('ServerProtocol')

    def __init__(self, socket, handler):
        super().__init__(socket)
        self.handler = handler
        self.continueReceiveLoop = False

    def loop(self):
        """ wait for client messages, process them, until client closes the connection"""
        try:
            self.setup()
            while self.continueReceiveLoop:
                if self.requireToken:
                    try:
                        m = self.receiveMessage(messaging.Message.CSendToken,
                                messaging.Message.Close)
                    except UnexpectedMessage:
                        raise AccessRestricted("Unknown Members are not "
                            "accepted. Get invited into a share group or ask"
                            " the server operator for a token to become a"
                            " registered user.")
                else:
                    m = self.receiveMessage()
                t = m.TYPE

                try:
                    h = getattr(self, 'handle_' + t)
                except AttributeError as e:
                    raise NotImplementedError('handle_' + t) from e
                h(m)  # delegate the message to handle_XXX
        except AccessRestricted as e:
            logger.warning("Client has insufficient rights", exc_info=e)
            self.sendErrorMessage("AccessRestricted", "%s", e.args[0])
        except ClientError as e:
            logger.warning("Client did something wrong", exc_info=e)
            self.sendErrorMessage("ClientError", *e.args)
        except CorruptMessage as e:
            logger.warning("Client sent corrupt Message, closing.", exc_info=e)
            # Send no details to the Client, those might be useful to break
            # crypto.
            self.sendErrorMessage("BadMessage")
        except UnexpectedMessage as e:
            logger.warning(
                "Client sent unexpected Message, closing.", exc_info=e)
            self.sendErrorMessage("BadMessage", "%r", e)
        except messaging.SocketClosed:
            logger.warning("Socket closed unexpectedly %r", self)
        except Exception as e:
            try:
                self.sendErrorMessage("ServerError")
            except:
                pass
            logger.error("Error %s", e, exc_info=e)
            raise
        finally:
            self.close()

    def requireToken(self, b):
        """ Set whether the client must send a token as first message after the
            key exchange.
        """
        self.requireToken = b

    def sendErrorMessage(self, code, msg="", *p):
        m = messaging.Message.SError(Code=code, Message=msg % p)
        self.sendMessage(m)

    def setup(self):
        """ First Set of messages to negotiate protocol version etc."""

        self.startCollecting()

        if not self.handler.acceptClientByAddress():
            self.close()
            return

        m = self.receiveMessage(messaging.Message.CHello)
        cv = m.getProtocolVersion()

        if cv != self.PROTOCOL_VERSION:
            raise CorruptMessage("Unknown Protocol Version %d" % cv)

        client_cs = set(m.getCipherSuites())

        # Handler selects one that the client accepts and the server prefers
        cs = self.handler.getCipherSuite(client_cs)
        sk = self.handler.getServerPublicKey()

        m = messaging.Message.SHello(
            ProtocolVersion=self.PROTOCOL_VERSION,
            ServerPublicKey=sk,
            SelectedCipherSuite=cs
        )
        self.sendMessage(m)

        HASH_METHOD, ENCRYPTION_METHOD = utilcrypto.CIPHER_SUITES[cs]
        symmetric_algo = crypto.getSymmetricEncryptionAlgorithm(
            ENCRYPTION_METHOD)
        key_size = symmetric_algo.getKeySize()

        # Server generates random bytes key_s
        # sends them encrypted to the client
        # client sends encrypted random bytes (key_c_enc)
        # decrypt them (key_c)
        #
        # x = hash(hash(key_c) + hash(key_s))
        # take client to server and server to client key from start of
        # Key Material = x + hash(x) + hash(hash(x)) + ...

        key_s = crypto.getRandomBytes(key_size)

        m = self.receiveMessage(messaging.Message.KeyExchange)
        if not m.getStep() == "HR-Client":
            raise CorruptMessage("Expected KeyExchange Step C1",
                                 "Got " + m.getStep())

        data = m.getData()
        if not isinstance(data, list) or len(data) != 2:
            raise CorruptMessage("Not a 2-tuple")
        key_c_enc, clientUserKey = data

        key_c_enc = serialize.base64decode(key_c_enc)
        key_c = self.handler.decrypt_with_server_key(key_c_enc)

        key_s_enc = utilcrypto.encrypt_asymmetric(key_s, clientUserKey)
        m = messaging.Message.KeyExchange(
            Step="HR-Server",
            Data=serialize.base64encode(key_s_enc)
        )
        self.sendMessage(m)

        def hash(data):
            h = crypto.getHashAlgorithm(HASH_METHOD)
            h.update(data)
            return h.digest()

        b = hash(hash(key_c) + hash(key_s))
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

        enc = symmetric_algo.getEncryptor(key_server_to_client, iv)
        dec = symmetric_algo.getDecryptor(key_client_to_server, iv)
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


        # if the handler does not accept the client, forbid everything except
        # sending tokens.
        self.requireToken = not self.handler.acceptClientByPublicKey(clientUserKey)
        self.continueReceiveLoop = True

    def handle_CRequestNewVersionsForItems(self, m):
        itemsWithVersion = m.getItems()

        itemsWithVersion = list(itemsWithVersion)
        SIZE_LIMIT = 300  # DECISION
        if len(itemsWithVersion) > SIZE_LIMIT:
            raise CorruptMessage(
                "no lookups for more than %d items", SIZE_LIMIT)

        v = self.handler.getNewItemVersions(itemsWithVersion)
        v = list(v)
        m = messaging.Message.SSendNewItemVersions(Versions=v)
        self.sendMessage(m)

    def handle_CRequestItemVersion(self, m):
        itemId = m.getItemId()
        versionId = m.getVersionId()

        metaData, contentIter, size = self.handler.getItemVersion(
            itemId, versionId)
        data = dict(
            ItemId=itemId,
            VersionId=metaData['versionId'],
            EncryptedItemKey=metaData['encryptedItemKey'],
            EncryptionMethod=metaData['encryptionMethod'],
            CompressionMethod=metaData['compressionMethod'],
            HashMethod=metaData['hashMethod'],
            ContentEncryptionIV=metaData['contentEncryptionIV'],
            TypeEncryptionIV=metaData['typeEncryptionIV'],
            EncryptedContentType=metaData['encryptedContentType'],
            HashEncryptionIV=metaData['hashEncryptionIV'],
            EncryptedContentHash=metaData['encryptedContentHash'],
        )

        shareId = metaData['shareId']
        if shareId is not None:
            data['ShareId'] = shareId

            x = metaData['itemKeyEncryptionIV']
            assert x is not None
            data['ItemKeyEncryptionIV'] = x

            x = metaData['itemKeyEncryptionMethod']
            assert x is not None
            data['ItemKeyEncryptionMethod'] = x

            x = metaData['encryptedShareKey']
            assert x is not None
            data['EncryptedShareKey'] = x

        m = messaging.Message.SSendItemVersion(**data)
        self.sendMessage(m)
        self.sendBlobFromIter(contentIter, size)

    def handle_CNewItemVersion(self, m):
        itemId = m.getItemId()
        if m.hasOldVersionId():
            oldVersionId = m.getOldVersionId()
            # Add a version to Item
            versioningScheme = None
            assert not m.hasVersioningScheme()
        else:
            # Add new Item
            oldVersionId = None
            versioningScheme = m.getVersioningScheme()

        if m.hasShareId():
            shareId = m.getShareId()
            if not m.hasItemKeyEncryptionIV():
                raise CorruptMessage(
                    "share but no ItemKeyEncryptionIV")
            itemKeyEncryptionIV = m.getItemKeyEncryptionIV()
        else:
            shareId = None
            if m.hasItemKeyEncryptionIV():
                raise CorruptMessage(
                    "no share but ItemKeyEncryptionIV")
            itemKeyEncryptionIV = None

        # Store Metadata
        res = self.handler.addItemVersion(
            itemId=m.getItemId(),
            oldVersionId=oldVersionId,

            shareId=shareId,
            itemKeyEncryptionIV=itemKeyEncryptionIV,
            encryptedItemKey=m.getEncryptedItemKey(),
            versioningScheme=versioningScheme,

            encryptionMethod=m.getEncryptionMethod(),
            compressionMethod=m.getCompressionMethod(),
            hashMethod=m.getHashMethod(),

            contentEncryptionIV=m.getContentEncryptionIV(),

            typeEncryptionIV=m.getTypeEncryptionIV(),
            encryptedContentType=m.getEncryptedContentType(),

            hashEncryptionIV=m.getHashEncryptionIV(),
            encryptedContentHash=m.getEncryptedContentHash()
        )

        success, newVid, offendingVid, contentUnchanged = res

        if success:
            if contentUnchanged:
                # already have the content
                m = messaging.Message.SReceivedItemVersion(
                    ItemId=m.getItemId(),
                    Accept=True,
                    NewVersionId=newVid,
                    SendContent=False)
            else:
                # Tell client to send Content
                m = messaging.Message.SReceivedItemVersion(
                    ItemId=m.getItemId(),
                    Accept=True,
                    SendContent=True)
        else:
            # Tell client that there is a version of the item he does not know
            m = messaging.Message.SReceivedItemVersion(
                ItemId=m.getItemId(),
                Accept=False,
                OffendingVersionId=offendingVid)

        self.sendMessage(m)

        if not success or contentUnchanged:
            return

        # Get the Content
        data, _ = self.receiveBlobIter()

        success, offendingVid = self.handler.storeItemVersionData(
            dataIter=data,
            itemId=itemId,
            newVersionId=newVid,
            oldVersionId=oldVersionId)

        if not success:
            # Tell client that there is a version of the item he does not know
            m = messaging.Message.SReceivedItemVersion(
                ItemId=m.getItemId(),
                Accept=False,
                OffendingVersionId=offendingVid)
        else:
            # Content Stored Successfully
            m = messaging.Message.SReceivedItemVersion(
                ItemId=m.getItemId(),
                Accept=True,
                NewVersionId=newVid)

        self.sendMessage(m)

    def handle_CCreateShare(self, m):
        shareId = self.handler.createShare(
            name=m.getName(),
            encryptionMethod=m.getEncryptionMethod(),
            macMethod=m.getShareMemberAuthenticationMethod(),
            fingerprintMethod=m.getFingerprintMethod()
        )

        m = messaging.Message.SNewShare(ShareId=shareId)
        self.sendMessage(m)

    def handle_CAddShareMember(self, m):
        shareId = m.getShareId()

        self.handler.addShareMember(
            shareId=shareId,
            email=m.getEmail(),
            permissions=m.getPermissions(),
            userPublicKey=m.getUserPublicKey(),
            shareKeyForUser=m.getEncryptedShareKey(),
            auth=m.getMemberAuthentication()
        )

        m = messaging.Message.SShareUpdated(ShareId=shareId)
        self.sendMessage(m)

    def handle_CUpdateShareMember(self, m):
        shareId = m.getShareId()

        self.handler.updateShareMember(
            shareId=shareId,
            oldKey=m.getOldUserPublicKey(),
            email=m.getEmail(),
            permissions=m.getPermissions(),
            userPublicKey=m.getUserPublicKey(),
            shareKeyForUser=m.getEncryptedShareKey(),
            auth=m.getMemberAuthentication()
        )

        m = messaging.Message.SShareUpdated(ShareId=shareId)
        self.sendMessage(m)

    def handle_CGetShare(self, m):
        shareId = int(m.getShareId())

        shareData, shareMembers = self.handler.getShare(
            shareId=shareId,
            forMe=m.getForMe()
        )

        MT = messaging.Message.SSendShare
        T = MT.MembersParam

        def pack(rec):
            assert rec['userPublicKey']['type'] == 'public'
            return T(
                Email=rec['email'],
                Permissions=rec['permissions'],
                UserPublicKey=rec['userPublicKey'],
                EncryptedShareKey=serialize.base64encode(
                    rec['shareKeyForUser']),
                MemberAuthentication=rec['auth']
            )
        shareMembers = list(map(pack, shareMembers))

        m = MT(
            ShareId=shareData['shareId'],
            Owner=shareData['ownerEmail'],
            Name=shareData['name'],
            EncryptionMethod=shareData['encryptionMethod'],
            ShareMemberAuthenticationMethod=shareData['macMethod'],
            FingerprintMethod=shareData['fingerprintMethod'],
            Members=shareMembers
        )
        self.sendMessage(m)

    def handle_CQueryShares(self, m):
        if m.hasName():
            name = m.getName()
        else:
            name = None
        ids = self.handler.queryShares(name)
        m = messaging.Message.SQuerySharesResult(ShareIds=ids)
        self.sendMessage(m)

    def handle_CSendToken(self, m):
        accept = self.handler.acceptClientByToken(m.getToken())
        m = messaging.Message.SAcceptToken(Accept=accept)
        self.sendMessage(m)

    def handle_Ping(self, m):
        self.sendMessage(m)

    def handle_Close(self, m):
        self.continueReceiveLoop = False
        self.close()
