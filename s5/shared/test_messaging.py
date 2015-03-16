from unittest.mock import Mock
from . import crypto
import pdb
import datetime
import queue
import logging
import time
import threading
import socket
import random
import io
import unittest

from . import messaging
from . import serialize


class TestUtil:

    class SendSocket:
        buffer = b''

        def sendall(self, b):
            self.buffer = self.buffer + b

    class RecvSocket:

        def __init__(self, b):
            self.buff = b

        def recv(self, bs):
            bs = random.randint(1, bs)
            b = self.buff[:bs]
            self.buff = self.buff[bs:]
            return b

    Message = messaging.DefineMessageType(
        "TestMessage",
        "Used only in tests",
        dict(
            Param1=dict(required=True, doc="no Doc", type=None),
            Param2=dict(required=False, doc="no Doc 2", type=int)).items()
    )

    def __init__(self):
        raise NotImplementedError("Dont do this")


class TestMessageTypes(unittest.TestCase):

    def test_messageParameterAccess(self):
        """ test if parameters work correctly

        wrong use of a closure in message.DefineMessageType caused
        all getters to return the same value """
        m = TestUtil.Message(Param1='value1', Param2=2)
        b = m.toBytes()
        self.assertIsInstance(b, bytes)
        m = messaging.Message.fromBytes(b)
        v = m.getParam1()
        self.assertEqual(v, 'value1')
        v = m.getParam2()
        self.assertEqual(v, 2)

    def test_requiredAndOptionalParams(self):
        with self.assertRaises(TypeError):
            TestUtil.Message(unknownparam=1)
        with self.assertRaises(TypeError):
            TestUtil.Message()
        with self.assertRaises(TypeError):
            TestUtil.Message(Param2="2")

        m = TestUtil.Message(Param1="1")
        self.assertEqual(m.getParam1(), "1")
        self.assertFalse(m.hasParam2())

        with self.assertRaises(AttributeError):
            m.hasParam1()

        m = TestUtil.Message(Param2=2, Param1="1")

        self.assertEqual(m.getParam1(), "1")
        self.assertTrue(m.hasParam2())
        self.assertEqual(m.getParam2(), 2)

    def test_typeErrors(self):
        with self.assertRaises(TypeError):
            TestUtil.Message(Param1="str", Param2=b'aaa')
        with self.assertRaises(TypeError):
            TestUtil.Message(Param1="str", Param2="str")

        TestUtil.Message(Param1="str", Param2=2)


class TestS5BaseProtocol(unittest.TestCase):

    def test_sendBlob(self):
        s = TestUtil.SendSocket()
        n = messaging.S5BaseProtocol(s)

        f = io.BytesIO()

        size = 10 * 1024

        b = bytes(range(0, 256))
        b = b * (size // len(b))
        f.write(b)

        f.seek(0)

        n.sendBlobFromIter(f, size)

        self.assertEqual(s.buffer[:16], b'BLOB/      2800:')
        self.assertEqual(s.buffer[16:], f.getvalue())

    def test_receiveBlob(self):
        size = 10 * 1024
        h = b'BLOB/      2800:'
        b = bytes(range(0, 256))
        b = b * (size // len(b))
        m = h + b
        s = TestUtil.RecvSocket(m)
        n = messaging.S5BaseProtocol(s)
        c, length = n.receiveBlobIter()
        self.assertEqual(b, b"".join(c))
        self.assertEqual(length, size)

    def test_message(self):
        s = TestUtil.SendSocket()
        n = messaging.S5BaseProtocol(s)

        m = TestUtil.Message(Param1='value', Param2=2)
        n.sendMessage(m)

    def test_receiveBlobSecured(self):
        key = b'\x00' * 16
        iv = key

        data = b'Test Data ' * 37

        a = crypto.getSymmetricEncryptionAlgorithm('aes-128-cbc-pkcs7pad')

        enc = a.getEncryptor(key, iv)
        dec = a.getDecryptor(key, iv)
        out_hasher = crypto.getHashAlgorithm('sha1')
        in_hasher = crypto.getHashAlgorithm('sha1')

        # Data Frame with Header and Encrypted Data
        data_frame = b'BLOB/       180:'

        enc.putPlain(data)
        enc.finish()
        enc_data = b''
        while enc.hasMore():
            enc_data += enc.getEncrypted()
        size = len(enc_data)
        assert size == 384

        data_frame += enc_data

        # hash all bytes
        out_hasher.update(data_frame)
        hash = out_hasher.digest()

        verify_frame = b'HASH/        20:'
        enc.continueUsing()
        enc.putPlain(hash)
        enc.finish()
        enc_data = b''
        while enc.hasMore():
            enc_data += enc.getEncrypted()
        assert len(enc_data) == 32

        verify_frame += enc_data

        # The following line corrupts the hash verification:
        #data_frame = data_frame[:23] + b'\x00' + data_frame[24:]

        # The following line corrupts the decryption:
        #data_frame = data_frame[:383] + b'\x00'

        s = TestUtil.RecvSocket(data_frame + verify_frame)
        n = messaging.S5BaseProtocol(s)

        n.secureConnection(None, dec, None, in_hasher)

        c, length = n.receiveBlobIter()
        self.assertEqual(data, b"".join(c))
        self.assertEqual(length, size)

    def test_sendBlobEncrypting(self):
        key = b'\x00' * 16
        iv = key

        data = b'Test Data ' * 37

        a = crypto.getSymmetricEncryptionAlgorithm('aes-128-cbc-pkcs7pad')

        enc = a.getEncryptor(key, iv)
        dec = a.getDecryptor(key, iv)
        out_hasher = crypto.getHashAlgorithm('sha1')
        in_hasher = crypto.getHashAlgorithm('sha1')

        size = len(data)

        s = TestUtil.SendSocket()

        n = messaging.S5BaseProtocol(s)
        n.secureConnection(enc, None, out_hasher, None)

        n.sendBlobFromIter([data], size)


        self.assertEqual(s.buffer[:16], b'BLOB/       180:')
        self.assertEqual(s.buffer[-48:-32], b'HASH/        20:')

        encrypted_data = s.buffer[16:-48]
        dec.putEncrypted(encrypted_data)
        dec.finish()
        decrypted_data = b''
        while dec.hasMore():
            decrypted_data += dec.getDecrypted()
        self.assertEqual(data, decrypted_data)

        in_hasher.update(s.buffer[:-48]) # hash over complete first frame
        hash = in_hasher.digest()

        encrypted_data = s.buffer[-32:]
        dec.continueUsing()
        dec.putEncrypted(encrypted_data)
        dec.finish()
        decrypted_data = b''
        while dec.hasMore():
            decrypted_data += dec.getDecrypted()
        self.assertEqual(hash, decrypted_data)


class TestProtocol(unittest.TestCase):
    TIME_OUT = 0.1

    def test_protocol(self):
        """ Test if Client and ServerProtocol communicate correctly """
        ss = socket.socket()
        ss.bind(('localhost', 0))
        ss.listen(1)
        addr = ss.getsockname()
        logger = logging.getLogger('TestProtocol')

        errorQueue = queue.Queue(100)

        def server():
            try:
                ss.settimeout(self.TIME_OUT)
                con, addr = ss.accept()

                con.settimeout(self.TIME_OUT)
                sp = messaging.S5BaseProtocol(con)

                m = sp.receiveMessage(TestUtil.Message)
                p1 = m.getParam1()
                p2 = m.getParam2()
                sp.sendMessage(TestUtil.Message(Param1=2 * p1, Param2=4 * p2))

                it, size = sp.receiveBlobIter()
                b = b''.join(it)
                b = b.decode("UTF-8").upper().encode("UTF-8")
                # Tes if small pieces arive
                it = iter([b[:3], b[3:7], b[7:8], b[8:]])
                sp.sendBlobFromIter(it, size)

            except Exception as e:
                errorQueue.put(e)
            finally:
                try:
                    ss.close()
                except:
                    pass
                try:
                    sp.close()
                except:
                    pass

        def client():
            try:
                cs = socket.socket()
                cs.settimeout(self.TIME_OUT)
                cs.connect(addr)
                cp = messaging.S5BaseProtocol(cs)

                m = TestUtil.Message(Param1=3, Param2=7)
                cp.sendMessage(m)
                m = cp.receiveMessage()
                self.assertEqual(m.getParam1(), 6)
                self.assertEqual(m.getParam2(), 28)

                cp.sendBlobFromIter(iter([b'hans', b'fred', b'test']), 12)

                it, size = cp.receiveBlobIter()

                s = b''.join(it).decode("UTF-8")
                self.assertEqual(s, "HANSFREDTEST")
                self.assertEqual(size, 12)

            except Exception as e:
                errorQueue.put(e)
            finally:
                try:
                    cp.close()
                except:
                    pass

        serverThread = threading.Thread(target=server)
        clientThread = threading.Thread(target=client)
        serverThread.start()
        clientThread.start()

        serverThread.join()
        clientThread.join()
        x = None
        while True:
            try:
                e = errorQueue.get(False)
                raise e from x
            except queue.Empty:
                break
            except BaseException as e:
                x = e

        if x is not None:
            raise x

    def test_encryptedProtocol(self):
        """ Test if Client and ServerProtocol communicate correctly with
        activated encryption """

        key_cts = crypto.generateSymmetricEncryptionKey(16)
        key_stc = crypto.generateSymmetricEncryptionKey(16)
        iv = b'\x00' * 16
        symmetric_algo = crypto.getSymmetricEncryptionAlgorithm(
            'aes-128-cbc-pkcs7pad')

        ss = socket.socket()
        ss.bind(('localhost', 0))
        ss.listen(1)
        addr = ss.getsockname()
        logger = logging.getLogger('TestProtocol')

        errorQueue = queue.Queue(100)

        def server():
            try:
                enc = symmetric_algo.getEncryptor(key_stc, iv)
                dec = symmetric_algo.getDecryptor(key_cts, iv)

                ss.settimeout(self.TIME_OUT)
                con, addr = ss.accept()

                con.settimeout(self.TIME_OUT)
                sp = messaging.S5BaseProtocol(con)

                hi = crypto.getHashAlgorithm("sha1")
                ho = crypto.getHashAlgorithm("sha1")
                sp.secureConnection(enc, dec, hi, ho)

                m = sp.receiveMessage(TestUtil.Message)
                p1 = m.getParam1()
                p2 = m.getParam2()
                sp.sendMessage(TestUtil.Message(Param1=2 * p1, Param2=4 * p2))

                it, size = sp.receiveBlobIter()
                b = b''.join(it)
                b = b.decode("UTF-8").upper().encode("UTF-8")
                it = [b[:3], b[3:7], b[7:8], b[8:]]
                sp.sendBlobFromIter(it, len(b))

            except Exception as e:
                errorQueue.put(e)
            finally:
                try:
                    ss.close()
                except:
                    pass
                try:
                    sp.close()
                except:
                    pass

        def client():
            try:
                enc = symmetric_algo.getEncryptor(key_cts, iv)
                dec = symmetric_algo.getDecryptor(key_stc, iv)

                cs = socket.socket()
                cs.settimeout(self.TIME_OUT)
                cs.connect(addr)
                cp = messaging.S5BaseProtocol(cs)

                hi = crypto.getHashAlgorithm("sha1")
                ho = crypto.getHashAlgorithm("sha1")
                cp.secureConnection(enc, dec, hi, ho)

                m = TestUtil.Message(Param1=3, Param2=7)
                cp.sendMessage(m)
                m = cp.receiveMessage()
                self.assertEqual(m.getParam1(), 6)
                self.assertEqual(m.getParam2(), 28)

                cp.sendBlobFromIter(iter([b'hans', b'fred', b'test']), 12)

                it, size = cp.receiveBlobIter()

                s = b''.join(it).decode("UTF-8")
                self.assertEqual(s, "HANSFREDTEST")
                self.assertEqual(size, 16)

            except Exception as e:
                errorQueue.put(e)
            finally:
                try:
                    cp.close()
                except:
                    pass

        serverThread = threading.Thread(target=server)
        clientThread = threading.Thread(target=client)
        serverThread.start()
        clientThread.start()

        serverThread.join()
        clientThread.join()
        x = None
        while True:
            try:
                e = errorQueue.get(False)
                raise e from x
            except queue.Empty:
                break
            except BaseException as e:
                x = e

        if x is not None:
            raise x
