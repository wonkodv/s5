"""
    Make most client side functions available via a Command Line Interface 
"""


from ..shared import crypto
from ..shared import utilcrypto
from . import items
import os.path
import traceback
import shlex
import time
import stat
import argparse
import codecs
import getpass
import io
import json
import logging
import os
import re
import string
import subprocess
import sys
import tempfile
import textwrap

from pathlib import Path

from ..shared import serialize
from ..shared import permissions
from ..shared import conventions
from ..shared import util

from . import client
from . import callbacks
from . import sync
from . import filesync

from .net import AccessRestricted
from ..shared.conventions import ITEM_TYPES

logger = logging.getLogger(__name__)

CLIENT_VERSION_STRING = 'S5 CLI Client 0.1'


class ImpossibleInBatchMode(Exception):
    pass


class CliMixIn(
        sync.SyncMixin,
        filesync.FileSyncMixin,
        client.CatalogMixin,
        client.S5Client):
    
    """
        Functions that work with stdin and stdout and command line arguments.
        Catalog Paths are specified with slashes, like unix file paths.
    """

    def __init__(self, cb):
        super().__init__(cb)
        self.outStream = sys.stdout.buffer
        self.inStream = sys.stdin.buffer

    def getShareBySpec(self, server, spec):
        """ Get a share Id from a name or a share id """
        try:
            return int(spec)
        except:
            shareIds = self.queryShares(server, spec)
            if len(shareIds) == 1:
                return shareIds[0]
            elif len(shareIds) == 0:
                raise KeyError("No share with name %s on Server %s" %
                               (spec, server)) from None
            else:
                raise NotImplementedError("Select from these shares: %s" %
                                          shares) from None

    def getItemBySpec(self, spec):
        itemId = self.getItemIdBySpec(spec)
        return self.getItem(itemId)

    def getPathFromSpec(self, spec):
        """ Split path strings at / """
        path = spec.split('/')
        for p in path:
            m = self.ITEM_NAME_RE.fullmatch(p)
            if m is None:
                raise ValueError("Illegal name %s in %r" % (p, path))

        return path

    def getItemIdBySpec(self, spec):
        """ get item by path or  partial id or return the id"""

        assert isinstance(spec, str), "need str not %s" % type(spec)
        if spec == '/':
            return self.getRootItemId()

        if conventions.isItemId(spec):
            try:
                return self.getItem(spec).itemId
            except KeyError:
                pass

        path = spec.split('/')
        if len(path) >= 1:
            try:
                return self.getItemIdByPath(path)
            except KeyError:
                pass

        itemId = list(self.db_itemByPartialId(spec))
        if len(itemId) == 1:
            return itemId[0]['itemId']
        if len(itemId) >= 1:
            raise KeyError("Partial itemId %s not unique" % spec)

        if conventions.isItemId(spec):
            return spec
        raise KeyError("Cannot find item for %s" % spec)

    def printf(self, f, *params, ln="\n"):
        self.outStream.write((f % params + ln).encode('UTF-8'))

    def addItemToPath(self, path, parents=False, force=False, itemType=None):
        path = self.getPathFromSpec(path)
        if itemType is None:
            itemType = ITEM_TYPES.MAP
        item = self.newItem(itemType)
        if itemType == ITEM_TYPES.MAP:
            item.save()
        self.putItemByPath(
            item, path, create_parents=parents, overwrite_existing=force)
        return item

    def writeItem(self, path, parents=False, force=False, itemType=None):
        """ Write to an item from stdin """
        try:
            item = self.getItemBySpec(path)
            if not force:
                raise Exception("Item already exists")
        except KeyError:
            path = self.getPathFromSpec(path)
            if itemType is None:
                itemType = ITEM_TYPES.FILE
            item = self.newItem(itemType)
            self.putItemByPath(item, path, create_parents=parents)

        item.saveFromStream(self.inStream, io.DEFAULT_BUFFER_SIZE)
        return item

    def editFileItem(
            self,
            path,
            editor=None,
            saveChanges=False,
            parents=False,
            force=False,
            itemType=None,
            format_json=False):
        """ Open an item's content in an editor """
        try:
            item = self.getItemBySpec(path)
        except KeyError:
            if force:
                if itemType is None:
                    itemType = ITEM_TYPES.MAP
                path = self.getPathFromSpec(path)
                item = self.newItem(ITEM_TYPES.FILE)
                self.putItemByPath(item, path, create_parents=parents)
            else:
                raise

        with tempfile.NamedTemporaryFile() as tmp:
            if item.hasContent():
                if format_json:
                    b = item.getContentBytes()
                    try:
                        s = b.decode("UTF-8")
                        o = json.loads(s)
                        s = json.dumps(o, sort_keys=True, indent=4)
                        # unix tools expect a EOL as last char in a file
                        s += "\n"
                        b = s.encode('UTF-8')
                    except (UnicodeDecodeError, ValueError):
                        pass
                    tmp.write(b)
                else:
                    for b in item.getContentIterator():
                        tmp.write(b)
                tmp.flush()
                tmp.seek(0)

            if not editor:
                editor = os.environ.get('EDITOR', 'vim')

            p = Path(tmp.name)

            if saveChanges:
                p.chmod(stat.S_IRUSR | stat.S_IWUSR)  # only read, Write
                stat_before = p.stat()
            else:
                p.chmod(stat.S_IRUSR)  # only read

            editor = shlex.split(editor)
            command = editor + [tmp.name]
            subprocess.call(command)

            if saveChanges:
                stat_after = p.stat()

                if stat_after.st_mtime != stat_before.st_mtime:
                    item.saveFromStream(tmp)
                    self.printf("Saving new Content")
                else:
                    self.printf("Nothing Changed")
        assert not p.exists()

    def dumpItemContents(self, item):
        for x in item.getContentIterator():
            self.outStream.write(x)

    def hexDumpItemContents(self, item, maxLines, indent=""):
        """ Print item content like `xxd` """
        dump = False
        if maxLines:
            maxLines = maxLines * 16  # compared with line header(coutns Bytes)

        def blocks():
            buff = b''
            for x in item.getContentIterator():
                buff = buff + x
                while len(buff) >= 16:
                    yield buff[:16]
                    buff = buff[16:]
            yield buff

        def char(b):
            if 0x20 <= b <= 0x7e:
                return chr(b)
            return ('.')
        line = 0
        hexformat = " ".join(["%02X%02X"] * 8)
        for b in blocks():
            chars = "".join(char(x) for x in b)
            if len(b) == 16:
                hex = hexformat % tuple(b)
            else:
                hex = ""
                for i in range(len(b)):
                    hex = hex + "%02X" % b[i]
                    if i % 2 == 1:
                        hex = hex + " "
                hex = "%-39s" % hex

            self.printf('%s% 6X | %s | %s', indent, line, hex, chars)
            line = line + 16
            if maxLines and line > maxLines:
                break

    def prettyPrintJson(self, item, indent=""):
        b = item.getContentBytes()
        s = b.decode('utf-8')
        try:
            o = json.loads(s)
        except ValueError:
            self.printf('%s%s', indent, '<Not JSON>')
        else:
            s = json.dumps(o, sort_keys=True, indent=4)
            for l in s.split("\n"):
                self.printf('%s%s', indent, l)

    def printItemMeta(self, item, indent=''):
        uwi = item._wrapped
        data = (
            ("ItemId", uwi.itemId),
            ("Cont Type", uwi.decryptedContentType),
            ("EncAlg", uwi.encryptionMethod),
            ("Hash M", uwi.hashMethod),
            ("Hash M", uwi.compressionMethod),
        )
        if item.hasContent():
            data += (
                ("Enc Size", util.fileSizeFormat(uwi.sizeOfEncryptedContent)),
                ("Cont Hash", uwi.decryptedContentHash[:20] + '...'),
                ("M Time", uwi.lastModified),
            )
        self.printf("%s %s", indent, "Meta Data:")
        for k, v in data:
            self.printf("%s %9s: %s", indent, k, v)

    def printItemSyncInfo(self, item, indent='', server=None):
        syncs = list(
            self.db_getSyncs(itemIds=[item.getItemId()], server=server))
        if syncs:
            for sync in syncs:
                self.printf("%s Sync Info with %s:", indent, sync['server'])
                self.printf("%s %9s: %s", indent,
                            "Version ID", sync['versionId'])
                self.printf("%s %9s: %s", indent, "Last Sync", sync['time'])
                self.printf("%s %9s: %s", indent,
                            "Direction", sync['direction'])
                self.printf("%s %9s: %s", indent, "shareId", sync['shareId'])

                if item.encryptedContentHash != sync['encryptedContentHash']:
                    self.printf("%s %s", indent, "<Local Changes>")
                else:
                    self.printf("%s %s", indent, "<No Local Changes>")

        else:
            self.printf("%s %s", indent, "<Never Synchronized>")

    def printItemTree(
            self,
            name,
            item,
            depth=0,
            withId=True,
            meta=False,
            json=False,
            hex=False,
            sync=False,
            text=False,
            share=False):
        indent = ""

        shares = {}

        def visit(item, itemId, key, first, last, up, down, ids):
            nonlocal indent
            leaf = down and up
            level = len(ids)

            if level == 0:
                mainIndent = ""
                childIndent = " "
            elif last:
                mainIndent = "└──"
                childIndent = "    "
            else:
                mainIndent = "├──"
                childIndent = "│   "

            if leaf:
                infoIndent = "    "
            else:
                infoIndent = "│   "

            if key is None:
                key = name

            mainIndent = indent + mainIndent
            childIndent = indent + childIndent
            infoIndent = childIndent + infoIndent

            if not leaf:
                if down:
                    # Set for Children:
                    indent = childIndent
                else:
                    # UnSet for Parents/Siblings:
                    indent = indent[:-4]
                    return

            self.printf("%s%s", mainIndent, key)

            if withId:
                self.printf("%s %s", infoIndent, itemId)
            if item is None:
                self.printf("%s %s", infoIndent, "<Not Local>")
            else:
                if not item.hasContent():
                    self.printf("%s %s", infoIndent, "<Empty>")
                if type(item) == items.BaseAccessor:
                    self.printf("%s %s", infoIndent, "<Unsupported Type>")
                if meta:
                    self.printItemMeta(item, infoIndent)
                if json:
                    self.prettyPrintJson(item, infoIndent)
                if hex:
                    self.hexDumpItemContents(item, 10, infoIndent)
                if sync:
                    self.printItemSyncInfo(item, infoIndent)
                if share:
                    syncs = list(self.db_getSyncs([itemId]))
                    b = True
                    if syncs:
                        for s in syncs:
                            shareId = s['shareId']
                            serverName = s['server']
                            idx = (serverName, shareId)
                            if shareId:
                                b = False
                                if idx in shares:
                                    s = shares[idx]
                                else:
                                    s, _, _ = self.getShare(
                                        serverName, shareId)
                                    s = "%(Name)s %(ShareId)d" % s
                                    shares[idx] = s

                                self.printf(
                                    "%s Shared on %s with %s",
                                    infoIndent,
                                    serverName,
                                    s)
                    if b:
                        self.printf("%s %s", infoIndent, "<Not Shared>")
                if text:
                    if item.hasContent():
                        itemContent = item.getContentIterator()
                        o = io.StringIO()
                        l = 0
                        decoder = codecs.iterdecode(
                            itemContent, "UTF-8", 'replace')
                        for s in decoder:
                            l += len(s)
                            o.write(s)
                            if l > 1000:
                                decoder.close()
                                itemContent.close()
                        try:
                            width = os.get_terminal_size().columns
                        except OSError:
                            width = 70
                        width = max(30, width - len(infoIndent))
                        s = textwrap.wrap(
                            text=o.getvalue(),
                            width=width,
                            tabsize=4,
                            max_lines=10
                        )
                        for line in s:
                            self.printf("%s%s", infoIndent, line)

            if depth > 0:
                cont = len(ids) < depth
            else:
                cont = True

            if not leaf and not cont:
                self.printf("%s├──...", childIndent)
                self.printf("%s└──...", childIndent)

            return cont

        def loop(item, key, ids, data, first, last):
            if last:
                mainIndent = "├──"
            else:
                mainIndent = "└──"
            self.printf('%s%s LOOP: %r', data, mainIndent, item)
        self.walkItemTree(item, visit, loop)

    def printAllShareGroups(self, server=None, name=None, indent=''):
        if server is None:
            servers = (s['name'] for s in self.db_getAllServers())
        else:
            servers = [server]
        for server in servers:
            ids = self.queryShares(server, name)
            if ids:
                if name:
                    self.printf("%s Share Groups on %s with name %s", indent,
                                server, name)
                else:
                    self.printf("%s Share Groups on %s", indent, server)
            for shareId in ids:
                share, members, myMember = self.getShare(server, shareId)
                self.printf("%s %9s: %s", indent, "Share ID", share['ShareId'])
                self.printf("%s %9s: %s", indent, "Name", share['Name'])
                self.printf("%s %9s: %s", indent, "Owner", share['Owner'])
                perms = myMember['Permissions']
                perms = ", ".join(sorted(map(lambda x: x.name, perms)))
                self.printf("%s %30s: %s", indent, myMember['Email'], perms)
                if len(members) > 1:
                    self.printf("")
                    for m in members:
                        if m != myMember:
                            perms = m['Permissions']
                            perms = ", ".join(
                                sorted(map(lambda x: x.name, perms)))
                            self.printf(
                                "%s %30s: %s", indent, m['Email'], perms)

    def db_getAllServers(self):
        cur = self.db.cursor()
        try:
            cur.execute(
                "SELECT name,host,port,fingerprint,fingerprintMethod FROM server")
            return cur.fetchall()
        finally:
            cur.close()

    def db_itemByPartialId(self, spec):
        cur = self.db.cursor()
        try:
            cur.execute(
                "SELECT itemId FROM item WHERE itemId LIKE ?", (spec + '%',))
            return cur.fetchall()
        finally:
            cur.close()

    def addUserToShareWithTemp(self, server, shareId, email, perms):
        """ Add a user to share. if user not yet known, add a temporary key and
        send that to the user """

        share, members, myMember = self.getShare(server, shareId)

        for m in members:
            if m['Email'].lower() == email.lower():
                raise Exception("Already added")

        sharedItems = []
        reportItems = []
        path = []

        def visit(itemId, up, down, key, **_):
            cont = True
            if down:
                path.append(key)
                syncs = list(self.db_getSyncs(itemIds=[itemId], server=server))
                if len(syncs) == 1:
                    if syncs[0]['shareId'] == shareId:
                        sharedItems.append((key, itemId))
                        reportItems.append(tuple(path))
                        cont = False  # dont go to children
            if up:
                path.pop()
            return cont
        self.walkItemTree(self.getRootItem(), visit, False)

        if reportItems:
            self.printf("The Share Group has access to the following Items:")
            for p in reportItems:
                self.printf("* %s", "/".join(p[1:]))
        else:

            if not self.callbacks.askToSharingGroupWithnoItems(email):
                return

        tempKeyAlgo = crypto.getAsymmetricEncryptionAlgorithm(
            self.callbacks.getNewShareTemporaryAsymmetricKeyAlgo())

        tempPrivKey = tempKeyAlgo.generatePrivateKey()
        tempPubKey = tempKeyAlgo.getPublicFromPrivate(tempPrivKey)

        self.addUserToShare(server, shareId, email, perms, tempPubKey)
        self.printf("A Temporary Key was created and added to group %s for "
                    "user %s.", shareId, email)

        pw = utilcrypto.generatePassword(
            self.callbacks.getNewShareTemporaryKeyPasswordLength())

        serverData = self.db_getServer(server)
        sd = {}
        for k in "host", "port", "fingerprint", "fingerprintMethod":
            sd[k] = serverData[k]

        exportDict = {
            "TemporaryKey": tempPrivKey,
            "Server": sd,
            "ShareId": shareId,
            "Items": sharedItems
        }

        data = serialize.objToBytes(exportDict)
        algo = self.callbacks.getNewShareTemporaryKeyProtectionMethod()
        pbkdf = self.callbacks.getNewShareTemporaryKeyProtectionPBKDF()

        enc = utilcrypto.passwordProtectData(
            data=data,
            algo=algo,
            password=pw,
            pbkdf=pbkdf
        )

        _, path = tempfile.mkstemp(suffix=".S5Member")
        with open(path, 'wb') as f:
            f.write(enc)

        self.printf(
            "Submit the following file to %s to give him the"
            " temporary Key, the server Info, and the List of itemIds"
            " that can be accessed with this share along with the names"
            " they have in your catalog. The Key is protected with a"
            " password that you should transport seperately!"
            "\n\nFile: %s\nPassword: %s", email, path, pw)

    def becomeShareMemberFromTemp(self, filePath, password, item):
        """ takes the file and password from addUserToShareWithTemp"""

        with filePath.open('rb') as f:
            enc = f.read()

        data = utilcrypto.extractPasswordProtectedData(enc, password)

        data = serialize.bytesToObj(data)

        serverData = data['Server']
        for s in self.db_getAllServers():
            if serverData['host'] == s['host']:
                if serverData['port'] == s['port']:
                    server = s['name']
                    logger.info("Already know the server as %s", server)
                    break
        else:
            server = self.callbacks.getNameForAddedServer(serverData)
            self.addServer(server, **serverData)

        try:
            self.getShare(server, data['ShareId'], True)
        except AccessRestricted:
            pass  # Were not in that share yet
        else:
            raise Exception("Already in that share")

        self.replaceKeyInShareMemberWithOwn(
            server,
            data['ShareId'],
            data['TemporaryKey'])

        for name, itemId in data['Items']:
            if name in item:
                printf("No linked because already item contains that"
                       " name:\n%s\t%s", name, itemId)
            else:
                item.putId(name, itemId)
        item.save()

    def removeUnreachableItems(self):
        """ 
            Remove all local items that are not reachable in the item catalog
        """
        c = self.db.cursor()
        self.items = {}
        with self.db:
            try:
                c.execute("""
                    CREATE TEMPORARY TABLE gc AS
                        SELECT 
                            itemId 
                        FROM
                            item
                    """)

                sql100 = "DELETE FROM gc WHERE itemId in (" + \
                    ",".join(["?"] * 100) + ")"

                ids = self.iterateItemTree(self.getRootItem())
                for group in util.groupwiseIterator(ids, 100):
                    group = tuple(group)
                    if len(group) == 100:
                        sql = sql100
                    else:
                        sql = "DELETE FROM gc WHERE itemId in (" + \
                            ",".join(["?"] * len(group)) + ")"
                    c.execute(sql, group)

                c.execute(" SELECT itemId FROM gc")
                for row in c:
                    itemId = row['itemId']
                    p = self.getItemStorage(itemId)
                    p.unlink()
                    logger.debug("Collected unreachable Item %s", itemId)
                c.execute("""
                    DELETE FROM item 
                    WHERE itemId IN (
                        SELECT itemId
                        FROM gc)
                    """)
                c.execute("""
                    DELETE FROM sync 
                    WHERE itemId IN (
                        SELECT itemId
                        FROM gc)
                    """)
            finally:
                c.execute (""" DROP TABLE gc """)
                c.close()


class CliClient(CliMixIn, client.S5Client):

    """ The arguemtn parsing and function invocation for the CLI """

    def doArguments(self, o):
        """ do as the argument options `o` specify """

        # All comands specified as local functions here,
        def core_init():
            if o.key is not None:
                with o.key.open('rb') as f:
                    key = f.read()
                self.initializeWithExistingKey(key)
            else:
                self.initializeNew()

        def core_upgrade():
            self.upgrade()

        def core_export_key():
            encKey, pw = self.exportUserKey()
            _, path = tempfile.mkstemp(suffix=".S5Key")
            with open(path, 'wb') as f:
                f.write(encKey)

            self.printf(
                "Your private key was exported to %s, encrypted with %s",
                path,
                pw)

        def core_set_root_id():
            self.setRootId(o.id)

        def core_list_crypto():
            self.printf("The following cryptographic algorithms are "
                        "supported with your setup and can be configured to "
                        "be used in your configuration File:")

            self.printf("Symmetric Encryption")
            self.printf(", ".join(
                filter(
                    lambda s: s != 'null',
                    crypto.Algorithms.symmetricEncryptionAlgos)))
            self.printf("")

            self.printf("Asymmetric Encryption")
            self.printf(", ".join(crypto.Algorithms.asymmetricEncryptionAlgos))
            self.printf("")

            self.printf("Hash")
            self.printf(", ".join(crypto.Algorithms.hashAlgos))
            self.printf("")

            self.printf("Password Based Key Derivation")
            self.printf(", ".join(crypto.Algorithms.pbkdfAlgos))
            self.printf("")

            self.printf("Message Authentication")
            self.printf(", ".join(crypto.Algorithms.macAlgos))
            self.printf("")

            self.printf("Cipher Suites")
            self.printf(", ".join(
                filter(
                    lambda s: s.find('null') == -1,
                    utilcrypto.CIPHER_SUITES)))

        def server_list():
            for s in self.db_getAllServers():
                self.printf("%s", s['name'])
                self.printf("%9s: %s", "Host", s['host'])
                self.printf("%9s: %s", "Port", s['port'])

        def server_add():
            b = self.addServer(o.name, o.host, o.port, o.fingerprint_method,
                               o.fingerprint, o.force)
            if not b:
                self.printf("Server Added, but you are not authorized to "
                            "connect. Get an access token from the server "
                            "operator and submit with `s5 token`")
            else:
                self.printf("Server added")

        def server_token():
            if self.sendTokenToServer(o.server, o.token):
                self.printf("Token %s was accepted by server %s",
                            o.token, o.server)
            else:
                self.printf("Token %s was not accepted by server %s",
                            o.token, o.server)
                return 1

        def server_ping():
            start = time.time()
            d = self.pingServer(o.server)
            stop = time.time()
            self.printf("Server %s has a ping of %.1fms, connecting, pinging,"
                        " closing took %.1fms",
                        o.server, d, (stop - start) * 1000)

        def item_new():
            path = self.getPathFromSpec(o.path)
            self.addItemToPath(o.path, o.parents, o.force, o.type)

        def item_link():
            path = self.getPathFromSpec(o.path)
            itemId = self.getItemIdBySpec(o.item)
            self.putItemIdByPath(itemId, path, o.parents, o.force)

        def item_unlink():
            path = self.getPathFromSpec(o.path)
            p = path[:-1]
            n = path[-1]
            if p:
                i = self.getItemByPath(p)
            else:
                i = self.getRootItem()

            del i[n]
            i.save()

        def item_gc():
            self.removeUnreachableItems()

        def item_edit():
            self.editFileItem(
                o.item,
                o.editor,
                not o.ignore_changes,
                o.parents,
                o.force,
                o.type,
                o.json)

        def item_write():
            self.writeItem(o.item, o.parents, o.force, o.type)

        def item_open():
            self.editFileItem(o.item, 'xdg-open', True)

        def item_inspect():
            item = self.getItemBySpec(o.item)
            b = True
            if o.json:
                b = False
                self.prettyPrintJson(item)
            if o.sync:
                b = False
                self.printItemSyncInfo(item)
            if o.hex:
                b = False
                self.hexDumpItemContents(item, None)
            if o.share:
                b = False
                self.printItemShareInfo(item)
            if o.dump:
                b = False
                self.dumpItemContents(item)
                self.printf("")
            if o.meta or b:
                self.printItemMeta(item)

        def item_dump():
            item = self.getItemBySpec(o.item)
            self.dumpItemContents(item)

        def item_tree():
            if o.item == []:
                name = '/'
                item = self.getRootItem()
            else:
                item = self.getItemBySpec(o.item)
                name = o.item
            self.printItemTree(name, item,
                               depth=o.depth,
                               withId=o.id,
                               meta=o.meta,
                               json=o.json,
                               hex=o.hex,
                               sync=o.sync,
                               share=o.share,
                               text=o.text)

        def item_find():
            path = []
            ids = tuple(o.id)

            def visit(key, itemId, down, up, **_):
                if down:
                    path.append(key)

                    if itemId.startswith(ids):
                        self.printf("%s %s", "/".join(path[1:]), itemId)

                if up:
                    path.pop()

            self.walkItemTree(self.getRootItem(),
                              visit,
                              False)

        def sync_pull_version():
            itemId = self.getItemIdBySpec(o.item)
            self.synchronizeItemIdFromServerWithVersion(
                itemId, o.version, o.server)

        def sync_pull():
            itemId = self.getItemIdBySpec(o.item)
            depth = o.depth
            if depth is None:
                depth = o.recursive
            res = self.synchronizeItemIdsFromServer(
                [itemId],
                o.server,
                depth,
                overwriteLocalChanges=o.force)
            self.printf("Pulled %s from Server:", itemId)

            if res.unknown:
                self.printf("\nUnknown to the server: ")
                for x in res.unknown:
                    self.printf("%35s", x)

            if res.ignored:
                self.printf("\nIgnored (Already up to date):\n"
                            "%35s %15s", "Item Id", "Version")
                for x in res.ignored:
                    self.printf("%35s %15s", *x)

            if res.updated:
                self.printf(
                    "\nUpdated \n"
                    "%35s %14s %15s",
                    "ItemId",
                    "Old Version",
                    "New Version")
                for x in res.updated:
                    self.printf("%35s %15s %15s", *x)

            if res.forbidden:
                self.printf("\nYou do not have access:")
                for x in res.forbidden:
                    self.printf("%35s", x)

            if res.conflicts:
                self.printf(
                    "\nConflicts (local information would be"
                    " overwritten (to do that use -f)):\n"
                    "%35s %15s %15s",
                    "ItemId",
                    "LastSyncVersion",
                    "Server Version")
                for x in res.conflicts:
                    self.printf("%35s %15s %15s", *x)

        def _print_push_results(op, res):
            if res.ignored:
                self.printf("\nIgnored (Already up to date):\n"
                            "%35s %15s", "Item Id", "Version")
                for x in res.ignored:
                    self.printf("%35s %15s", *x)

            if op == 'share':
                if res.excluded:
                    self.printf("\nExcluded Items (they were already shared, "
                                "use -f to overwrite)\n"
                                "%35s %15s", "ItemId", "Share Group")
                    for x in res.excluded:
                        self.printf("%35s %14s", *x)
            else:
                if res.excluded:
                    self.printf(
                        "\nExcluded (Items were never synchronized (use" " -a/ dont use -n)")
                    for x in res.excluded:
                        self.printf("%35s", x)

            if res.updated:
                self.printf(
                    "\nUpdated \n"
                    "%35s %15s %15s",
                    "ItemId",
                    "Old Version",
                    "New Version")
                for x in res.updated:
                    self.printf("%35s %14s %15s", *x)

            if res.forbidden:
                self.printf("\nYou do not have access:")
                for x in res.forbidden:
                    self.printf("%35s", x)

            if res.conflicts:
                self.printf(
                    "\nConflicts (remote information would be"
                    " overwritten. To resolve, do:\n"
                    "* store the current content with `s5 item dump`\n"
                    "* get server version with `s5 sync pull -f`\n"
                    "* Merge the content (`s5 item edit`)\n"
                    "\n"
                    "%35s %15s %15s",
                    "ItemId",
                    "LastSyncVersion",
                    "newest Server Version")
                for x in res.conflicts:
                    self.printf("%35s %15s %15s", *x)

        def sync_push():
            item = self.getItemBySpec(o.item)
            res = self.synchronizeItemTreeToServer(
                item,
                o.server,
                addUnsynced=o.add_unsynced,
                addChildrenOfSynced=not o.dont_add_children)
            _print_push_results("push", res)

        def files_to_catalog():
            ctlgPath = self.getPathFromSpec(o.ctlgPath)
            fsPath = o.fsPath
            self.updateCatalogFromFileSystem(
                    ctlgPath, fsPath, o.update, o.parents)

        def share_list():
            self.printAllShareGroups(o.server, o.name)

        def share_new():
            shareId = self.createShare(o.server, o.name)
            self.printf("New Share %s", shareId)

        def share_add_item():
            shareId = self.getShareBySpec(o.server, o.group)
            item = self.getItemBySpec(o.item)

            res = self.shareItem(
                o.server, shareId, item, not o.non_recursive, o.force)
            _print_push_results("share", res)

        def share_add_user():
            shareId = self.getShareBySpec(o.server, o.group)
            if o.permissions == ['ALL']:
                perms = permissions.PermissionSet.ALL
            else:
                perms = permissions.PermissionSet(*o.permissions)
            if o.temp_key:
                self.addUserToShareWithTemp(o.server, shareId, o.user, perms)
            else:
                if o.from_share is None:
                    raise ValueError("Must Specify --temp-key or --from-share")
                other_share = self.getShareBySpec(o.from_share)
                self.addUserToShareFromOtherGroup(o.server, shareId, o.user,
                                                  perms, other_share)

        def share_become_member():
            item = self.getItemBySpec(o.item)
            pw = vars(o)['import-password']
            self.becomeShareMemberFromTemp(o.path, pw, item)

        def share_change_user_permissions():
            shareId = self.getShareBySpec(o.server, o.group)
            if o.permissions == ['NONE']:
                perms = permissions.PermissionSet()
            elif o.permissions == ['ALL']:
                perms = permissions.PermissionSet.ALL
            else:
                perms = permissions.PermissionSet(*o.permissions)
            self.changeShareMemberPermissions(o.server, shareId, o.user, perms)


        # Call the function the user wanted
        handlers = locals()

        try:
            if o.log_level is not None:
                logging.basicConfig(level=o.log_level)

            a = "%s_%s" % (o.component, o.action)
            a = a.replace('-', '_')

            try:
                h = handlers[a]
            except KeyError:
                raise NotImplementedError(a)
            result = h()
            if result is None:
                return 0
            return int(result)
        except Exception as e:
            try:
                st = o.stack_trace
            except:
                st = True  # somethig is really wrong

            if st:
                traceback.print_exc()
            else:
                print(repr(e))
            return 127


def main(o, inStream=None, outStream=None):
    """ Invoke the CliClient """
    callbacks = CliCallbacks(o)
    client = CliClient(callbacks)
    if outStream:
        client.outStream = outStream
    if inStream:
        client.inStream = inStream
    return client.doArguments(o)


def parseArgs(*args):
    p = argparse.ArgumentParser(
        description="Command Line Syncing Client",
        # TODO: Website
        epilog="Find help at <http:// (S5 has no website yet)>",
        prog='s5',
        add_help=True
    )
    p.add_argument(
        '-v',
        '--version',
        help='print version and exit',
        action='version',
        version=CLIENT_VERSION_STRING)

    p.add_argument(
        '--data',
        help='where data is stored',
        default=Path(os.path.expanduser('~/.s5')),
        type=Path)

    p.add_argument(
        '--log-level',
        help='Level of Logging'
    )

    p.add_argument(
        '--batch',
        help='Do not ask for user input',
        action='store_true'
    )

    p.add_argument(
        '--stack-trace',
        help='On errors, print the message with stacktrace',
        action='store_true'
    )

    component = p.add_subparsers(dest="component")
    component.required = True

# CORE
    cp = component.add_parser('core', help="Operations on the S5 Core")
    action = cp.add_subparsers(dest='action')
    action.required = True

    sp = action.add_parser('init', help='Initialize the client.')
    sp.add_argument('--key', help="Import a user key from this fiel instead of"
                    " creating a new one", type=Path)

    sp = action.add_parser('upgrade',
                           help="upgrade client data after the s5 software was updated")

    sp = action.add_parser('export-key',
                           help="Export the User Key")

    sp = action.add_parser('set-root-id',
                           help="Set the id of the catalog root item")
    sp.add_argument('id', help="The id of the root item")

    sp = action.add_parser('list-crypto',
                           help="List all possible cryptographic Algorihms")


# SERVER
    cp = component.add_parser('server', help="modify/show the list of servers")
    action = cp.add_subparsers(dest='action')
    action.required = True

    sp = action.add_parser('add', help='add or modify a Server')
    sp.add_argument('name', help="The anme by which the server will"
                    " be referrenced in other commands")
    sp.add_argument('host', help="IPv4 address, IPv6 address or domain name"
                    " of the server")
    sp.add_argument('port', type=int, help="TCP port the server listens on")
    sp.add_argument('-m', '--fingerprint-method', help="Use this method to"
                    " fingerprint the server's key")
    sp.add_argument(
        '-p',
        '--fingerprint',
        help="Ensure, that the server has this"
        " fingerprint")
    sp.add_argument(
        '-f',
        '--force',
        action='store_true',
        help="Overwrite existing Server (e.g. when the address changed)")

    sp = action.add_parser('list', help='list all servers')

    sp = action.add_parser('token', help='Send a token to the server')
    sp.add_argument('server', help='The Server to send to')
    sp.add_argument('token', help='The Token')

    sp = action.add_parser('ping', help='test connection')
    sp.add_argument('server', help='server to ping')

# ITEM
    cp = component.add_parser('item', help="list/modify items")
    action = cp.add_subparsers(dest='action')
    action.required = True

    sp = action.add_parser('gc', help='garbage collect')

    sp = action.add_parser('link', help='Link to an item under a path')
    sp.add_argument(
        '-f', '--force', help="overwrite existing", action='store_true')
    sp.add_argument(
        '-p', '--parents', help="create parents", action='store_true')
    sp.add_argument('item', help="the target, the complete item id of a non "
                    "local item, or the path or (partial) id of a local item")
    sp.add_argument('path', help="path by which the item should be accessible")

    sp = action.add_parser('unlink', help='remove an item from its parent')
    sp.add_argument('path', help="path Of item to unlink")

    sp = action.add_parser('write', help='fill item from stdin')
    sp.add_argument(
        '-f', '--force', help="overwrite existing", action='store_true')
    sp.add_argument(
        '-p', '--parents', help="create parents", action='store_true')
    sp.add_argument('-t', '--type', help="item type (default: file)")
    sp.add_argument('item', help="path to item")

    sp = action.add_parser('new', help='Create new Item')
    sp.add_argument(
        '-f', '--force', help="Overwrite existing", action='store_true')
    sp.add_argument(
        '-p', '--parents', help="Create Parents", action='store_true')
    sp.add_argument('-t', '--type', help="Item Type (default: Map)")
    sp.add_argument('path', help="path to new item")

    sp = action.add_parser('edit', help='Edit the item content in an editor')
    sp.add_argument('-i', '--ignore-changes',
                    help="Do not change the item content", action='store_true')
    sp.add_argument(
        '-t',
        '--type',
        help="Item Type to use if the item is created with -f. (default: File)")
    sp.add_argument(
        '-f', '--force', help="Create Item if not exists", action='store_true')
    sp.add_argument(
        '-p', '--parents', help="Create Parents", action='store_true')
    sp.add_argument(
        '-j',
        '--json',
        help="Format json content before editing.",
        action='store_true')
    sp.add_argument('-e', '--editor', help="Use this Editor")
    sp.add_argument('item', help="item id or path")

    sp = action.add_parser(
        'open', help='Open the file in the default program, ignore changes')
    sp.add_argument('item', help="item id or path")

    sp = action.add_parser('inspect', help='Inspect an Item')
    sp.add_argument(
        '--meta', help="print metadata (default)", action='store_true')
    sp.add_argument(
        '--hex', help="print Content Hex encoded", action='store_true')
    sp.add_argument(
        '--json', help="prettyPrint Json Content ", action='store_true')
    sp.add_argument(
        '--dump', help="dump content to stdout", action='store_true')
    sp.add_argument(
        '--sync', help="print synchronization Infos", action='store_true')
    sp.add_argument('--share', help="print sharing Infos", action='store_true')
    sp.add_argument('item', help="item id or path")

    sp = action.add_parser('dump', help='print item content')
    sp.add_argument('item', help="item id or path")

    sp = action.add_parser('tree', help='Inspect an Item Tree')
    sp.add_argument('--depth', help="max depth", type=int, default=0)
    sp.add_argument('--id', help="print ids", action='store_true')
    sp.add_argument('--meta', help="print metadata", action='store_true')
    sp.add_argument(
        '--text',
        help="print indented content (only printable ascii)",
        action='store_true')
    sp.add_argument(
        '--hex', help="print Content Hex encoded", action='store_true')
    sp.add_argument(
        '--json', help="prettyPrint Json Content ", action='store_true')
    sp.add_argument(
        '--sync', help="print synchronization Infos", action='store_true')
    sp.add_argument('--share', help="print sharing Infos", action='store_true')
    sp.add_argument('item', help="item id or path", nargs='?', default='/')

    sp = action.add_parser('find', help='Search for an item tree in path')
    sp.add_argument('id', help="(partial) item id to find", nargs="+")


# SYNC
    cp = component.add_parser('sync', help="Synchronize to/from Servers")
    action = cp.add_subparsers(dest='action')
    action.required = True

    sp = action.add_parser('push', help="Synchronize an item tree TO a server")
    sp.add_argument(
        '-s', '--server', help='server to sync with', required=True)
    sp.add_argument(
        '-a',
        '--add-unsynced',
        help='add items that were never synced',
        action='store_true')
    sp.add_argument(
        '-n',
        '--dont-add-children',
        help='do not add items that were never'
        ' synced if they have parents that were synced',
        action='store_true')
    sp.add_argument('item', help="item id or path")

    sp = action.add_parser('pull', help="Synchronize some items FROM a server")
    sp.add_argument(
        '-s', '--server', help='server to sync with', required=True)
    sp.add_argument('-r', '--recursive', help='synchronize child items'
                    ' recursively', action='store_true')
    sp.add_argument('-d', '--depth', help='same as -r but limit the recusion'
                    ' depth', type=int)
    sp.add_argument(
        '-f',
        '--force',
        help='Overwrite local changes with data from Server',
        action='store_true')
    sp.add_argument('item', help="item id or path")

    sp = action.add_parser(
        'pull-version', help="Get a version for an item from the server")
    sp.add_argument(
        '-s', '--server', help='server to sync with', required=True)
    sp.add_argument('-v', '--version', help='The version', type=int,
                    required=True)
    sp.add_argument('item', help="item id or path")


# SHARE
    cp = component.add_parser(
        'share', help="Change a sharing groups on a server")
    action = cp.add_subparsers(dest='action')
    action.required = True

    sp = action.add_parser('new', help="Create a share Group, owned by you")
    sp.add_argument('-s', '--server', help='The Server name', required=True)
    sp.add_argument('name', help='The name for the group (unique per user)')

    sp = action.add_parser('add-item', help="Add an item tree to a group")
    sp.add_argument('-s', '--server', help='The Server name', required=True)
    sp.add_argument(
        '-n',
        '--non-recursive',
        help='Dont apply recursively',
        action='store_true')
    sp.add_argument(
        '-f',
        '--force',
        help='Change the group of already shared items',
        action='store_true')
    sp.add_argument('group', help='The id or name for the group')
    sp.add_argument('item', help="item id or path")

    sp = action.add_parser('list', help="List all groups")
    sp.add_argument('-s', '--server', help='The Server name', required=False)
    sp.add_argument('--name', help='The Group name', required=False)

    sp = action.add_parser('add-user', help="Add a user to a group")
    sp.add_argument('-s', '--server', help='The Server name', required=True)
    sp.add_argument('group', help='The id or name for the group')
    sp.add_argument('user', help='The email of the user to add')
    sp.add_argument('permissions', nargs="+", help='The permissions')
    sp.add_argument('--temp-key', help='Add the user using a temporary key',
                    action='store_true')
    sp.add_argument('--from-share', help='Add the user using the key he '
                    'has in this other share', type=int)

    sp = action.add_parser('become-member', help="Become a Group Member")
    sp.add_argument(
        'path',
        type=Path,
        help='The .S5Member- file you were sent by the group owner')
    sp.add_argument('import-password', help='Password protecting the file')
    sp.add_argument(
        'item',
        help="item id or path of the item to put all new shared items in")
    sp.add_argument('--server-name',
                    help='If it is a new Server, give it this name')
    sp.add_argument('-m', '--fingerprint-method', help="Use this method to"
                    " fingerprint the server's key, for a new server")
    sp.add_argument(
        '-f',
        '--fingerprint',
        help="Ensure, that the server has this"
        " fingerprint, for a new server")

    sp = action.add_parser(
        'change-user-permissions', help="Change a users Permissions")
    sp.add_argument('-s', '--server', help='The Server name', required=True)
    sp.add_argument('group', help='The id or name for the group')
    sp.add_argument('user', help='The email of the user to add')
    sp.add_argument('permissions', nargs="+", help='The permissions')

# FILES
    cp = component.add_parser(
        'files', help="Synchronize between S5 and FileSystem")
    action = cp.add_subparsers(dest='action')
    action.required = True

    sp = action.add_parser(
        'to-catalog', help="Update the Item Catalog from the FileSystem")
    sp.add_argument(
        'ctlgPath',
        help="Path in the catalog to map the files in")
    sp.add_argument('fsPath', help="Path to a file or directory", type=Path)
    sp.add_argument(
        '-u', '--update', action='store_true', help="Update existing items")
    sp.add_argument(
        '-p', '--parents', help="Create Parents", action='store_true')

    if len(args) == 0:
        args = None

    return p.parse_args(args)


class CliCallbacks(callbacks.ConfigCallbacks):

    """ Callbacks for the Client """

    def __init__(self, options):
        self.options = options
        super().__init__(options.data)

    def askForPasswordToImportUserKey(self):
        p = os.environ.get('S5_IMPORT_PASSWORD', None)
        if p is not None:
            return p
        if self.options.batch:
            raise ImpossibleInBatchMode("Must specify password in environment"
                                        " variable S5_IMPORT_PASSWORD for batchmode")
        print("Enter password to import User Key ", file=sys.stderr)
        pw = getpass.getpass()
        return pw

    def askForUserKeyPassword(self):
        p = os.environ.get('S5_PASSWORD', None)
        if p is not None:
            return p
        if self.options.batch:
            raise ImpossibleInBatchMode("Must specify password in environment"
                                        " variable S5_PASSWORD for batchmode")
        print("Enter password for User Key ", file=sys.stderr)
        pw = getpass.getpass()
        return pw

    def askForNewUserKeyPassword(self):
        p = os.environ.get('S5_PASSWORD', None)
        if p is not None:
            return p
        if self.options.batch:
            raise ImpossibleInBatchMode("Must specify password in environment"
                                        " variable S5_PASSWORD for batchmode")
        print(
            "Choose a passphrase to protect the user key on disk",
            file=sys.stderr)
        while True:
            print("Enter new password: ", file=sys.stderr)
            pw = getpass.getpass()
            print("Enter new password again: ", file=sys.stderr)
            pw2 = getpass.getpass()
            if pw == pw2:
                return pw

    def getNewServerAsymmetricKeyFingerprintMethod(self):
        if self.options.fingerprint_method:
            return self.options.fingerprint_method
        return super().getNewServerAsymmetricKeyFingerprintMethod()

    def verifyNewServerFingerprint(self, fp, fpm):
        if self.options.fingerprint:
            return self.options.fingerprint == fp
        if self.options.batch:
            raise ImpossibleInBatchMode("Must specify a fingerprint of the"
                                        " server with --fingerprint for batchmode")
        return self._askYesNoQuestion("Is the server Fingerprint %s: %s "
                                      "correct?", fpm, fp)

    def getEmailToUseInShares(self):
        try:
            return super().getEmailToUseInShares()
        except KeyError:
            pass
        if self.options.batch:
            raise ImpossibleInBatchMode("No email address configured but "
                                        "using batchmode")
        s = input("Your Email Address in Shares: ")
        return s

    def _askYesNoQuestion(self, question, *args):
        if self.options.batch:
            raise ImpossibleInBatchMode()
        i = ""
        while not i in ("Y", "y", "yes", "N", "n", "no"):
            print(question % args + " [n/y]", file=sys.stderr)
            i = input()

        return i in ("Y", "y", "yes")

    def askToSharingGroupWithnoItems(self, email):
        if self.options.batch:
            return True
        return self._askYesNoQuestion(
            "The Share Group has no "
            "access to any Items."
            "They can be added later, but have to be transmitted to"
            "%s seperately. continue anyways? " %
            email)

    def getNameForAddedServer(self, serverData):
        if self.options.server_name is not None:
            return self.options.server_name
        if self.options.batch:
            return True

        return input("Name for server %(host)s:%(port)d: " % serverData)
