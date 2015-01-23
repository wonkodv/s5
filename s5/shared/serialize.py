""" 
    Various methods to convert between objects, bytes and strings
"""

import base64
import json


def strToBytes(s):
    b = s.encode("UTF-8")
    return b


def bytesToStr(b):
    s = b.decode("UTF-8")
    return s


def objToStr(obj):
    return json.dumps(obj)


def strToObj(s):
    return json.loads(s)


def objToBytes(obj):
    """ convert Obj to JSON-String, UTF-8 encode, return bytes """
    return strToBytes(objToStr(obj))


def bytesToObj(b):
    """ utf-8 decode bytes, decode JSON-String, return Object"""
    return strToObj(bytesToStr(b))


def base64decode(s):
    """ b64decode string, return bytes """
    return base64.standard_b64decode(s.encode('ASCII'))


def base64encode(b):
    """ b64Encode bytes, return as ASCII String """
    return base64.standard_b64encode(b).decode('ASCII')
