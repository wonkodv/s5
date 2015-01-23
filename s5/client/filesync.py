"""
    This module allows synchronization between files and items
"""


from pathlib import Path
import datetime
import logging
import mimetypes

from . import client
from ..shared.conventions import ITEM_TYPES
from ..shared import utilcrypto


logger = logging.getLogger(__name__)


class FileSyncMixin(client.CatalogMixin):

    """ stores files as FILE items and directories as MAP"""

    DIRECTORY_ITEM_TYPE = '%s(%s)' % (ITEM_TYPES.MAP, ITEM_TYPES.FILE)

    def _itemForPath(self, fsPath):
        """ Make an Item for the FileSystemPath"""

        if fsPath.is_file():
            t, e = mimetypes.guess_type(fsPath.name)
            s = None
            if t is not None:
                if e is not None:
                    pass
                else:
                    s = "%s(%s)" % (ITEM_TYPES.FILE, t)

            if s is None:
                s = ITEM_TYPES.FILE

            return self.newItem(s)
        elif fsPath.is_dir():
            return self.newItem(self.DIRECTORY_ITEM_TYPE)
        else:
            raise TypeError("not file or dir: %s?" % p)

    def updateItemFromFile(self, item, filePath):
        """ update the item if file is newer """
        assert item.TYPE == ITEM_TYPES.FILE

        ti = item.getLastModified()

        tf = filePath.stat().st_mtime
        tf = datetime.datetime.fromtimestamp(tf)

        h = item.getContentHash()

        mod = False
        if h is None:
            logger.debug("Item is new: %s %s", filePath, item)
            mod = True
        elif tf > ti:
            if not utilcrypto.fileHashEqual(
                    item.getHashMethod(),
                    filePath,
                    h):
                logger.debug(
                    "File has newer MTime and different Content: %s (%s) %s",
                    filePath, tf, item)
                mod = True
            else:
                logger.debug("File has newer MTime but same Content:" +
                             " %s (%s) %s", filePath, tf, item)
                item.saveWithModTime(tf)
        if mod:
            logger.info("Updating item %s from File %s", item, filePath)
            item.saveFromPath(filePath)
            item.saveWithModTime(tf)

    def updateCatalogFromFileSystem(self, itemPath, fsPath,
            update_existing=False, create_parents=True):
        """ synchronize a file or directory at `fsPath` to item(s) at
        `itemPath` """
        assert len(itemPath)>0
        try:
            item = self.getItemByPath(itemPath)
        except KeyError:
            item = self._itemForPath(fsPath)
            self.putItemByPath(item, itemPath, create_parents=create_parents)
        else:
            if not update_existing:
                raise Exception("Already Exists:",itemPath)

        self._updateCatalogFromFileSystem(item, fsPath)

    def _updateCatalogFromFileSystem(self, item, fsPath):
        """ Make Items for all Files, and Directories on the FS,
        fill File Items with File's content if file is newer than item"""
        if fsPath.is_file():
            self.updateItemFromFile(item, fsPath)
        elif fsPath.is_dir():
            if item.getContentType() != self.DIRECTORY_ITEM_TYPE:
                if item.getContentType() != ITEM_TYPES.MAP:
                    raise TypeError("Not a Directory(%s) %r, %s" %
                                    (self.DIRECTORY_ITEM_TYPE, item, fsPath))
            leftOverItems = set(item.keys())
            for fsChild in fsPath.iterdir():
                name = fsChild.name
                try:
                    itemChild = item[name]
                    leftOverItems.remove(name)
                except KeyError:
                    itemChild = self._itemForPath(fsChild)
                    item[name] = itemChild
                self._updateCatalogFromFileSystem(itemChild, fsChild)
            for n in leftOverItems:
                logger.info("File was deleted: %s, %s, %s", n, fsPath, item)
                del item[n]
            item.save()
