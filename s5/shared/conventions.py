""" Constants and related methods """

import re

ITEM_ID_RE = re.compile("^[A-Z0-9]{32}$")

def isItemId(itemId):
    match = ITEM_ID_RE.fullmatch(itemId)
    return match is not None

class ITEM_TYPES:
    JSON = "urn:x-s5:json"
    MAP = "urn:x-s5:map"
    LIST = "urn:x-s5:list"
    FILE = "urn:x-s5:file"
