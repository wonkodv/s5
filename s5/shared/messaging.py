"""
    Everything for the network communication that is shared by client and
    server.
"""

from . import conventions
import collections
import collections.abc
import logging
import io

from . import serialize
from .util import addAttribute

from .permissions import PermissionSet

from .crypto import DecryptionError



# The message classes are all mostly identical and therefor generate
# from a list of Tuples with
#   -   Message Type
#   -   Message Description
#   -   Message Parameters: a list of tuples of
#       *   Parameter Name
#       *   Parameter Spec, a dict with keys:
#       *   doc
#       *   required
#       *   type
#       *   tupleNames

MessageParams = (
    (
        "SError",
        """ Sent by the server when something unexpected happens, followed by
            closing the connection. """,
        (
            (
                "Code",
                {
                    "doc": """A code indicating what type of problem occurred.
                        Any of `ClientError`, `AccessRestricted`, `BadMessage`
                        or `ServerShutDown`. """,
                    "required": True,
                    'type': str
                }
            ),
            (
                "Message",
                {
                    "doc": "String describing what happened.",
                    "required": True,
                    'type': str
                },
            )
        )
    ),
    (
        "Ping",
        """ Does nothing but can be used to measure round trip time. """,
        (
        )
    ),
    (
        "SRequireProofOfWork",
        """ Sent by the server to slow down an attack or prevent spam.""",
        (
            (
                "Method",
                {
                    "doc": "The name of a POW method, e.g. `Hash` or `Captcha`.",
                    "required": True,
                    'type': str
                }
            ),
            (
                "Params",
                {
                    "doc": "A single parameter or a list of parameters.",
                    "required": True,
                    'type': None
                }
            )
        )
    ),
    (
        "CHaveProof",
        """ Clients response to `SRequireProofOfWork`. """,
        (
            (
                "Proof",
                {
                    "doc": "The proof that the server requested.",
                    "required": True,
                    'type': None
                }
            ),
        )
    ),
    (
        "CHello",
        """ First message sent by the client to
            negotiate protocol and encryption for the rest of
            the connection. """,
        (
            (
                "ProtocolVersion",
                {
                    "doc": "The highest protocol version, the client knows.",
                    "required": True,
                    'type': int,
                }
            ),
            (
                "CipherSuites",
                {
                    "doc": """List of names of methods for encrypted communication.""",
                    "required": True,
                    "type": list
                }
            ),
        )
    ),
    (
        "SHello",
        """ The server's response to `CHello`. """,
        (
            (
                "ProtocolVersion",
                {
                    "doc": "The protocol used in this session.",
                    "required": True,
                    "type": int
                }
            ),
            (
                "ServerPublicKey",
                {
                    "doc": "The public key of the server.",
                    "required": True,
                    "type": "publickey"
                }
            ),
            (
                "SelectedCipherSuite",
                {
                    "doc": "The encryption method chosen by the server to use.",
                    "required": True,
                    "type": str
                }
            ),
        )
    ),
    (
        "KeyExchange",
        """ Several messages used for the key exchange,
            depending on the method chosen by the server. """,
        (
            (
                "Step",
                {
                    "doc": "Name of the step.",
                    "required": True,
                    "type": str
                }
            ),
            (
                "Data",
                {
                    "doc": "The data exchanged in this step.",
                    "required": True,
                    "type": None
                }
            ),
        )
    ),
    # Below Messages are sent encrypted
    (
        "NegotiationVerification",
        """ Sent as first encrypted message by both parties, verifying that the
            negotiation was not manipulatead.""",
        (
        )
    ),
    # Secure connection established, Client sends requests
    (
        "CSendToken",
        """ The client sends a token that the server can use to map the
            client's public key to an account that the server uses to manage
            the user base. 
        """,
        (
            (
                "Token",
                {
                    "doc": """ A token, password or similar. """,
                    "required": True,
                    "type": str
                }
            ),
        )
    ),
    (
        "SAcceptToken",
        """ The server's response to `CSendToken` """,
        (
            (
                "Accept",
                {
                    "doc": """ Whether the server accepts the token. """,
                    "required": True,
                    "type": bool
                }
            ),
        )
    ),
    (
        "CRequestNewVersionsForItems",
        """ Request meta data for items with `ItemId`, exclude information if
            `VersionId` is the most recent version. """,
        (
            (
                "Items",
                {
                    "doc":  """ List of tuples """,
                    "tupleNames": ("ItemId", "VersionId"),
                    "required": True,
                    "type": list
                }
            ),
        )
    ),
    (
        "SSendNewItemVersions",
        """ Response to `CRequestNewVersionsForItems`. Send the `VersionId` for
            items that have changes the client does not know. Send 'unknown' or
            'unauthorized' instead of the `VersionId` for items not on the server
            or where the client has no access. """,
        (
            (
                "Versions",
                {
                    "doc": """ List of tuples """,
                    "tupleNames": ("ItemId", "VersionId"),
                    "required": True,
                    "type": list
                }
            ),
        )
    ),
    (
        "CRequestItemVersion",
        """ Request the meta data and content of an item at a version. """,
        (
            (
                "ItemId",
                {
                    "doc": "The item id.",
                    "required": True,
                    'type': 'itemId'
                },
            ),
            (
                "VersionId",
                {
                    "doc": "The version of the item. ",
                    "required": True,
                    'type': int
                }
            ),
        )
    ),
    (
        "SSendItemVersion",
        """ Response to `CRequestItemContent`. Followed by a BLOB with the
        content. """,
        (
            (
                "ItemId",
                {
                    "doc": "The item id. ",
                    "required": True,
                    "type": "itemId"
                }
            ),
            (
                "VersionId",
                {
                    "doc": "The version of the item. ",
                    "required": True,
                    "type": int,
                }
            ),
            (
                "EncryptionMethod",
                {
                    "doc": "The method for encrypting content and meta data. ",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "HashMethod",
                {
                    "doc": "The hash method. ",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "CompressionMethod",
                {
                    "doc": "The method to compress the item content. ",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "ContentEncryptionIV",
                {
                    "doc": "The initialization vector used to encrypt the item content. ",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "TypeEncryptionIV",
                {
                    "doc": "The initialization vector used to encrypt the content hash. ",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "EncryptedContentType",
                {
                    "doc": "The encrypted type of the item. ",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "EncryptedContentHash",
                {
                    "doc": "The encrypted hash of the item content. ",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "HashEncryptionIV",
                {
                    "doc": "The initialization vector used to encrypt the content hash. ",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "EncryptedItemKey",
                {
                    "doc": """The symmetric key of the item, encrypted with the
                        share key  or the owners asymmetric key. """,
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "ShareId",
                {
                    "doc": "The id of the share group, if the item is shared. ",
                    "required": False,
                    "type": int,
                }
            ),
            (
                "EncryptedShareKey",
                {
                    "doc": """ The share key encrypted with the user's public key as
                        stored in the share member.  """,
                    "required": False,
                    "type": bytes,
                }
            ),
            (
                "ItemKeyEncryptionMethod",
                {
                    "doc": """The method with which the item key is encrypted using
                            the share key.  """,
                    "required": False,
                    "type": str,
                }
            ),
            (
                "ItemKeyEncryptionIV",
                {
                    "doc": """ The initialization vector that is used to
                    encrypt the item key with the share key.  """,
                    "required": False,
                    "type": bytes,
                }
            ),
        )
    ),
    (
        "CNewItemVersion",
        """ Sent for an item version to the server. If the client believes the
            item to be new, no `OldVersionId` is sent but a `VersioningScheme`. If
            the server does not have an item with that itemId, a new one is created
            with that VerisoningScheme and the client is set as owner.

            SReceivedItemVersion is sent in response, telling the client,
            whether the version was accepted, whether the content must be sent
            (only needed if encryptedContentHash changed) the new versionId or
            the offendingVersionId.
        """,
        (
            (
                "ItemId",
                {
                    "doc": "The item id.",
                    "required": True,
                    "type": "itemId",
                }
            ),
            (
                "OldVersionId",
                {
                    "doc":  """The version id from the previous synchronization.
                        Omitted for items that were never synchronized.""",
                    "required": False,
                    "type": int,
                }
            ),
            (
                "VersioningScheme",
                {
                    "doc":  """ If the item is new to the server, this scheme should be
                            used for versioning.""",
                    "required": False,
                    "type": str,
                }
            ),
            (
                "EncryptionMethod",
                {
                    "doc": "The method for encrypting content and meta data.",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "HashMethod",
                {
                    "doc": "The hash method.",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "CompressionMethod",
                {
                    "doc": "The method to compress the item content.",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "ContentEncryptionIV",
                {
                    "doc": "The initialization vector used to encrypt the item content.",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "TypeEncryptionIV",
                {
                    "doc": "The initialization vector used to encrypt the content hash.",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "EncryptedContentType",
                {
                    "doc": "The encrypted type of the item.",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "EncryptedContentHash",
                {
                    "doc": "The encrypted hash of the item content.",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "HashEncryptionIV",
                {
                    "doc": "The initialization vector used to encrypt the content hash.",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "EncryptedItemKey",
                {
                    "doc": """The symmetric key of the item, encrypted with the
                        share key  or the owners asymmetric key.""",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "ShareId",
                {
                    "doc": "The id of the share group, if the item is shared.",
                    "required": False,
                    "type": int,
                }
            ),
            (
                "ItemKeyEncryptionIV",
                {
                    "doc": """ The initialization vector that is used to
                    encrypt the item key with the share key.  """,
                    "required": False,
                    "type": bytes,
                }
            ),
        )
    ),
    (
        "SReceivedItemVersion",
        """ Can be sent in response to `CNewItem` or `CUpdateItem`,
            telling, whether the new version is accepted and, if it was
            not, `OffendingVersionId` contains the version, that the client did
            not have. If it was accepted, the server determines, if the
            `EncryptedContentHash` changed. If not, the new version is complete
            and `NewVersionId` contains the id of the new Version. If the
            `EncryptedContentHash` did change, `SendContent` is set to True, and
            the client has to send the content for the new version.
            After the content was received, this message is sent again,
            signaling, whether the content was accepted. If so, `Accept` is set
            to `True` and the `NewVersionId` is sent. Otherwise,
            `Accept` is set to `False` and the `OffendingVersionId` is sent.
        """,
        (
            (
                "ItemId",
                {
                    "doc": "The item id.",
                    "required": True,
                    "type": "itemId"
                }
            ),
            (
                "Accept",
                {
                    "doc": """Whether the server accepts.""",
                    "required": True,
                    "type": bool,
                }
            ),
            (
                "SendContent",
                {
                    "doc": """Whether the client should send the content.""",
                    "required": False,
                    "type": bool,
                }
            ),
            (
                "OffendingVersionId",
                {
                    "doc": "Id of the version that the client would have overwritten.",
                    "required": False,
                    "type": int,
                }
            ),
            (
                "NewVersionId",
                {
                    "doc": "Id of the version the update was saved as, or that appeared during upload.",
                    "required": False,
                    "type": int,
                }
            ),
        )
    ),
    (
        "CDeleteItem",
        """ Deletes an Item from the Server.  """,
        (
            (
                "ItemId",
                {
                    "doc": "The item id.",
                    "required": True,
                    "type": "itemId",
                }
            ),
        )
    ),
    (
        "CCreateShare",
        """ Creates a new share group, the client becomes the owner. """,
        (
            (
                "Name",
                {
                    "doc": """A name for the group, unique per owner. """,
                    "required": True,
                    "type": str,
                }
            ),
            (
                "EncryptionMethod",
                {
                    "doc": """The method with which item keys will be encrypted for
                        this share group.""",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "ShareMemberAuthenticationMethod",
                {
                    "doc": """The method with which members of this share group
                                will be authenticated. """,
                    "required": True,
                    "type": str,
                }
            ),
            (
                "FingerprintMethod",
                {
                    "doc": """ The method to derive fingerprints from asymmetric keys
                        for authentication.""",
                    "required": True,
                    "type": str,
                }
            ),
        )
    ),
    (
        "SNewShare",
        """ Response to CCreateShare with new ShareId. """,
        (
            (
                "ShareId",
                {
                    "doc": "The identifier of the new share group.",
                    "required": True,
                    "type": int,
                }
            ),
        )
    ),
    (
        "CGetShare",
        """ The client requests information about a share. """,
        (
            (
                "ShareId",
                {
                    "doc": "The identifier of the share group.",
                    "required": True,
                    "type": int,
                }
            ),
            (
                "ForMe",
                {
                    "doc": "Only information for this user is requested.",
                    "required": False,
                    "type": bool,
                }
            ),
        )
    ),
    (
        "SSendShare",
        """ Response to `CGetShare` with information about a share group. """,
        (
            (
                "ShareId",
                {
                    "doc": "The Identifier of the share.",
                    "required": True,
                    "type": int,
                }
            ),
            (
                "Name",
                {
                    "doc": "The group name. ",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "Owner",
                {
                    "doc": "The group owner's email. ",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "EncryptionMethod",
                {
                    "doc": """The method with which item keys will be encrypted for
                        this share group. """,
                    "required": True,
                    "type": str,
                }
            ),
            (
                "ShareMemberAuthenticationMethod",
                {
                    "doc": """The method with which members of this share group will be
                                authenticated. """,
                    "required": True,
                    "type": str,
                }
            ),
            (
                "FingerprintMethod",
                {
                    "doc": """ The method to derive fingerprints from asymmetric keys
                        for authentication.""",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "Members",
                {
                    "doc": "List of tuples ",
                    "tupleNames": ["Email", "Permissions", "UserPublicKey",
                                   "EncryptedShareKey", "MemberAuthentication"],
                    "required": True,
                    "type": list,
                }
            ),
        )
    ),
    (
        "CAddShareMember",
        """ Adds a member to a share group. """,
        (
            (
                "ShareId",
                {
                    "doc": "The identifier of the share group.",
                    "required": True,
                    "type": int,
                }
            ),
            (
                "Email",
                {
                    "doc": "The email of the user. ",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "Permissions",
                {
                    "doc": "A list of permissions.",
                    "required": True,
                    'type': PermissionSet
                }
            ),
            (
                "UserPublicKey",
                {
                    "doc": "The public key of the user.",
                    "required": True,
                    "type": "publickey",
                }
            ),
            (
                "EncryptedShareKey",
                {
                    "doc": "The symmetric key of the share group, encrypted for the user. ",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "MemberAuthentication",
                {
                    "doc": """The authentication, guaranteeing that the public key
                        belongs to the user.""",
                    "required": True,
                    "type": str,
                }
            ),
        )
    ),
    (
        "CUpdateShareMember",
        """ Updates a member of a share group.""",
        (
            (
                "ShareId",
                {
                    "doc": "The identifier of the share group. ",
                    "required": True,
                    "type": int,
                }
            ),
            (
                "OldUserPublicKey",
                {
                    "doc": "The public key of the user before the change.",
                    "required": True,
                    "type": "publickey",
                }
            ),
            (
                "Email",
                {
                    "doc": "The new email of the user.",
                    "required": True,
                    "type": str,
                }
            ),
            (
                "Permissions",
                {
                    "doc": "A bit mask of the new permissions for the user. ",
                    "required": True,
                    'type': PermissionSet
                }
            ),
            (
                "UserPublicKey",
                {
                    "doc": "The new public key of the user.",
                    "required": True,
                    "type": "publickey",
                }
            ),
            (
                "EncryptedShareKey",
                {
                    "doc": "The new symmetric key of the share group, encrypted for the user.",
                    "required": True,
                    "type": bytes,
                }
            ),
            (
                "MemberAuthentication",
                {
                    "doc": """The new authentication, guaranteeing that the public key
                        belongs to the user. """,
                    "required": True,
                    "type": str,
                }
            ),
        )
    ),
    (
        "CDeleteShareMember",
        """ Delete a member of a share group.""",
        (
            (
                "ShareId",
                {
                    "doc": "The identifier of the share group. ",
                    "required": True,
                    "type": int,
                }
            ),
            (
                "UserPublicKey",
                {
                    "doc": "The public key of the user.",
                    "required": True,
                    "type": "publickey",
                }
            ),
        )
    ),
    (
        "CChangeShareOwnership",
        """ Make another member of a share group the owner.""",
        (
            (
                "ShareId",
                {
                    "doc": "The identifier of the share group. ",
                    "required": True,
                    "type": int,
                }
            ),
            (
                "UserPublicKey",
                {
                    "doc": "The public key of the user that should become"
                        " the new Owner.",
                    "required": True,
                    "type": "publickey",
                }
            ),
        )
    ),
    (
        "SShareUpdated",
        """ Response to `CAddShareMember`, `CUpdateShareMember`,
        `CDeleteShareMember` or `CChangeShareOwnership`.""",
        (
            (
                "ShareId",
                {
                    "doc": "The identifier of the share group that was changed.",
                    "required": True,
                    "type": int,
                }
            ),
        )
    ),

    (
        "CQueryShares",
        """ Get share groups for the user. """,
        (
            (
                "Name",
                {
                    "doc": "The name of the share group.",
                    "required": False,
                    "type": str,
                }
            ),
        )
    ),
    (
        "SQuerySharesResult",
        """ Get share groups for the user. """,
        (
            (
                "ShareIds",
                {
                    "doc": "A list of share group ids.",
                    "required": True,
                    "type": list,
                }
            ),
        )
    ),


    (
        "Close",
        """ Sent by either party before closing the connection. """,
        (
        )
    ),
)

class NetworkError(Exception):
    pass

class UnexpectedMessage(NetworkError):

    def __init__(self, msg, expectedTypes):
        self.message = msg
        self.expectedTypes = expectedTypes
        super().__init__(
            "Expected %s but got %r" % (
                set(e.TYPE for e in expectedTypes),
                msg)
        )


class CorruptMessage(NetworkError):
    pass


class SocketClosed(NetworkError):
    pass


class Message(collections.abc.Mapping):
    """ Basic Handler to convert parameter lists into json serialized bytes and
    backwards"""
    def toBytes(self):
        """ Serialize this Message """
        data = self.get_data_for_network()
        data['MessageType'] = self.TYPE
        return serialize.objToBytes(data)

    REGISTERED_MESSAGES = {}

    @classmethod
    def fromBytes(cls, _bytes):
        d = serialize.bytesToObj(_bytes)
        t = d['MessageType']
        del d['MessageType']
        return cls.REGISTERED_MESSAGES[t](
            from_network=True,
            **d)

    def __repr__(self):
        return "%r(%r)" % (self.TYPE, dict(self))


def ensureType(data, typ, for_network=False, from_network=False):
    """ verify a parameters type.
        convert if neccessary, for example base64 encode bytes before sending
        and decode after sending.
    """
    assert not (for_network and from_network)
    if typ is None:
        return data

    if for_network:
        if typ == bytes:
            return serialize.base64encode(data)
        if typ == PermissionSet:
            return [p.name for p in data]

    if typ == 'itemId':
        if conventions.isItemId(data):
            return data
    if typ == 'publickey':
        if data['type'] == 'public':
            return data
    if isinstance(data, typ):
        return data

    if from_network:
        if typ == bytes:
            return serialize.base64decode(data)
        if typ == PermissionSet:
            return PermissionSet(*data)
    raise TypeError("Expected: " + str(typ), "got: " + repr(data))


def DefineMessageType(name, doc, parameters):
    """ Turn 1 message definition into a Message-subclass """
    for p in parameters:
        if len(p) != 2:
            raise TypeError("No 2-tuple", name, p)
        k, spec = p
        if not isinstance(k, str):
            raise TypeError("No string", k)

        if not 'type' in spec:
            raise ValueError(name, k, "has no type")

    def __init__(self, from_network=False, **kwargs):
        data = {}
        for k, spec in parameters:
            if k not in kwargs:
                if spec['required']:
                    raise TypeError(
                        "missing keyword argument '%s' for %s()" % (k, name))
            else:
                typ = spec.get('type', None)
                try:
                    data[k] = ensureType(
                        kwargs[k],
                        typ,
                        from_network=from_network)
                except TypeError as e:
                    raise TypeError(
                        "Message " + name, "Parameter " + k, *e.args)
                del kwargs[k]

        if kwargs:
            raise TypeError(
                "invalid keyword argument(s) '%s' for %s()" % (kwargs.keys(), name))

        self.__data = data

    def get_data_for_network(self):
        data = {}
        for k, spec in parameters:
            typ = spec.get('type', None)
            if k in self.__data:
                data[k] = ensureType(self.__data[k], typ, for_network=True)
        return data

    def __getitem__(self, k):
        return self.__data.__getitem__(k)

    def __iter__(self):
        return self.__data.__iter__()

    def __len__(self):
        return self.__data.__len__()

    attributes = dict(
        __init__=__init__,
        __getitem__=__getitem__,
        __iter__=__iter__,
        __len__=__len__,
        get_data_for_network=get_data_for_network
    )

    def addAttributes(key, spec):
        # in seperate function so key is not modified (the closure captures the
        # variable, not the value it seems)
        doc = "Get the " + key + '\n\n' + spec['doc']
        if "tupleNames" in spec:
            n = key + "Param"
            ttyp = collections.namedtuple(n, spec["tupleNames"])
            attributes[n] = ttyp
            doc = doc + str(spec['tupleNames'])

            def getter(self):
                return map(ttyp._make, self.__data[key])
        else:
            def getter(self):
                try:
                    val = self.__data[key]
                    return val
                except KeyError:
                    raise AttributeError("Message %s has no Attribute %s "
                                         "(try has%s)"
                                         % (name, key, key))

        getter.__doc__ = doc
        attributes['get' + key] = getter

        if not spec['required']:
            def has(self):
                return key in self.__data
            has.__doc__ = "Whether " + key + " is part of the message"
            attributes['has' + key] = has

    for key, spec in parameters:
        addAttributes(key, spec)

    cls = type(name, (Message,), attributes)
    cls.TYPE = name
    cls.__doc__ = doc

    Message.REGISTERED_MESSAGES[name] = cls
    setattr(Message, name, cls)

    return cls

for m in MessageParams:
    DefineMessageType(*m)


class S5BaseProtocol:

    """ Wrapper arround a socket that sends and receives Messages or BLOBs """

    PROTOCOL_VERSION = 1

    HEADER_FORMAT = "% 4s/% 10X:"
    HEADER_SIZE = 4 + 1 + 10 + 1

    TYPE_MESSAGE = 'JSON'
    TYPE_BLOB = 'BLOB'
    TYPE_VERIFICATION = 'HASH'

    MAX_MESSAGE_SIZE = 2 ** 20  # DECISION 2MB
    MAX_BLOB_SIZE = 2 * (2 ** 30)  # DECISION: 2 GB
    MAX_HASH_SIZE = 100  # DECISION 100B

    def __init__(self, socket):
        self.socket = socket
        self.buff = b''
        self.collectIncoming = None
        self.collectOutgoing = None

        self.secured = False

        self._open = True

    def __repr__(self):
        if self._open:
            addr = "connected %s -> %s" % (self.socket.getsockname(),
                                           self.socket.getpeername())
        else:
            addr = 'closed'

        return "%s %s" % (type(self).__name__, addr)

    def isOpen(self):
        return self._open

    def getRemoteAddress(self):
        return self.socket.getpeername()

    def secureConnection(self, encryptor, decryptor, out_hasher, in_hasher):
        """ Install en/decryptors and hashers. The connection is encrypted and
        integrity checked after that.
        """
        self.secured = True
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.in_hasher = in_hasher
        self.out_hasher = out_hasher

    def startCollecting(self):
        self.collectIncoming = io.BytesIO()
        self.collectOutgoing = io.BytesIO()

    def stopCollecting(self):
        i = self.collectIncoming.getvalue()
        o = self.collectOutgoing.getvalue()
        self.collectIncoming = None
        self.collectOutgoing = None
        return i, o

    def _receive(self, size):
        """ receive until there are `size` bytes, return them"""
        self.buff = self.buff[size:]
        while len(self.buff) < size:
            try:
                b = self.socket.recv(size - len(self.buff))
            except OSError as e:
                raise NetworkError(str(e)) from e
            if len(b) == 0:
                raise SocketClosed()
            self.buff = self.buff + b
        b = self.buff[: size]
        self.buff = self.buff[size:]

        if self.collectIncoming:
            self.collectIncoming.write(b)

        if self.secured:
            self.in_hasher.update(b)
        
        return b

    def _send(self, b):
        if self.collectOutgoing:
            self.collectOutgoing.write(b)
        if self.secured:
            self.out_hasher.update(b)
        self.socket.sendall(b)

    def _encodeHeader(self, typ, length):
        assert length >= 0
        s = self.HEADER_FORMAT % (typ, length)
        b = s.encode('UTF-8')
        assert len(b) == self.HEADER_SIZE
        return b

    def _receiveHeader(self):
        b = self._receive(self.HEADER_SIZE)
        s = b.decode('UTF-8')
        typ = s[:4]
        slash = s[4:5]
        length = s[5:15]
        colon = s[15:16]
        if slash != '/' or colon != ':':
            raise NetworkError("invalid header: %s" % s)
        try:
            length = int(length, 16)
        except ValueError:
            raise NetworkError("invalid header: %s" % s)
        return typ, length

    

    def _receiveVerification(self):
        """ Receive a verification Frame and test if the hash over the bytes
        ent by the other party, matches the hash over the bytes received here.
        """
        assert self.secured

        h = self.in_hasher.digest()

        typ, length = self._receiveHeader()
        if not typ == self.TYPE_VERIFICATION:
            raise NetworkError("Not a Hash", typ)
        if length > self.MAX_HASH_SIZE:
            raise NetworkError("Too large", length)
        b = self._receive(length)

        d = self.decryptor
        try:
            d.putEncrypted(b)
            d.finish()
            dec = b''
            while d.hasMore():
                dec += d.getDecrypted()
            d.continueUsing()
            b = dec
        except DecryptionError as e:
            raise CorruptMessage("Decrypts wrong") from e

        if b != h:
            raise CorruptMessage("Verification Hashes do not match", b,h)

    def _sendVerification(self):
        """     
            Send a verification Frame with a hash over al bytes previously
            sent.
        """
        assert self.secured
        b = self.out_hasher.digest()

        if self.secured:
            e = self.encryptor
            e.putPlain(b)
            e.finish()
            b = b''
            while e.hasMore():
                b += e.getEncrypted()
            e.continueUsing()

        if len(b) > self.MAX_HASH_SIZE:
            raise NetworkError("Hash Too Large")

        h = self._encodeHeader(self.TYPE_VERIFICATION, len(b))

        self._send(h + b)

    def receiveMessage(self, *expectedTypes):
        """
            Wait for, and return a message, optionally specifying an expected
            type
        """
        typ, length = self._receiveHeader()
        if not typ == self.TYPE_MESSAGE:
            raise NetworkError("Not a Message: %s" % typ)
        if length > self.MAX_MESSAGE_SIZE:
            raise NetworkError("Too large: %d" % length)
        b = self._receive(length)

        if self.secured:
            try:
                d = self.decryptor
                d.putEncrypted(b)
                d.finish()
                dec = b''
                while d.hasMore():
                    dec += d.getDecrypted()
                d.continueUsing()
                b = dec
            except DecryptionError as e:
                raise CorruptMessage("Decrypts wrong") from e

        m = Message.fromBytes(b)
        if expectedTypes:
            for t in expectedTypes:
                if isinstance(m, t):
                    break
            else:
                raise UnexpectedMessage(m, expectedTypes)
        if self.secured:
            self._receiveVerification()
        return m

    def sendMessage(self, msg):
        """ Serialize and send a Message object """
        b = msg.toBytes()

        if self.secured:
            e = self.encryptor
            e.putPlain(b)
            e.finish()
            b = b''
            while e.hasMore():
                b += e.getEncrypted()
            e.continueUsing()

        if len(b) > self.MAX_MESSAGE_SIZE:
            raise NetworkError("Message Too Large")

        h = self._encodeHeader(self.TYPE_MESSAGE, len(b))

        self._send(h + b)

        if self.secured:
            self._sendVerification()

    def receiveBlobIter(self):
        """ Waits for a BLOB, yield its byte contnet in chuncks of arbitray
            size.
            returns an iterator and the length of the Frame, sent by the other
            side. If the data is encrypted, the length can be larger than the
            actual content due to padding.
        """
        typ, length = self._receiveHeader()
        if typ != self.TYPE_BLOB:
            raise NetworkError("Not a BLOB: %s" % typ)
        if length > self.MAX_BLOB_SIZE:
            raise NetworkError("Too large: %d" % length)

        bs = io.DEFAULT_BUFFER_SIZE

        if self.secured:
            def it():
                try:
                    d = self.decryptor
                    nonlocal length
                    while length > 0:
                        b = self._receive(min(bs, length))
                        length = length - len(b)
                        d.putEncrypted(b)
                        while d.hasMore():
                            yield d.getDecrypted()

                    d.finish()
                    while d.hasMore():
                        yield d.getDecrypted()
                    d.continueUsing()

                    self._receiveVerification()
                except DecryptionError as e:
                    raise CorruptMessage("Decrypts wrong") from e
        else:
            def it():
                nonlocal length
                while length > 0:
                    b = self._receive(min(bs, length))
                    length = length - len(b)
                    yield b

        return it(), length

    def sendBlobFromIter(self, dataIter, size):
        """ Read all bytes from dataIter and send as BLOB.
        """
        if not self.secured:
            b = self._encodeHeader(self.TYPE_BLOB, size)
            self._send(b)
            for b in dataIter:
                size = size - len(b)
                self._send(b)
        else:
            e = self.encryptor
            size = e.getSizeAfterEncryption(size)
            b = self._encodeHeader(self.TYPE_BLOB, size)
            self._send(b)
            for b in dataIter:
                e.putPlain(b)
                while e.hasMore():
                    b = e.getEncrypted()
                    size = size - len(b)
                    self._send(b)
            e.finish()
            while e.hasMore():
                b = e.getEncrypted()
                size = size - len(b)
                self._send(b)
            e.continueUsing()

            self._sendVerification()

        assert size == 0, 'Size was off by %d' % size

    def close(self):
        self._open = False
        self.socket.close()
