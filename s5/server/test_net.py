import queue
import socket
import threading
import unittest

from unittest.mock import Mock

from ..shared import messaging

from . import net


class testNet(unittest.TestCase):

    def test_server(self):

        def messageHandlerFactory(*args):
            from . import server
            handler = Mock(spec_set=server.ServerMessageHandler)
            handler.getServerPublicKey.return_value = 'Server Public Key'
            handler.getNewItemVersions.return_value = [
                {"ItemId": 'iid', "VersionId": 'vid'}]
            return handler

        q = queue.Queue(100)

        def exceptionHandler(socket, addr, e):
            q.put(e)

        s = net.NetworkServer(messageHandlerFactory, exceptionHandler)

        s.setup('localhost', 0)
        a = s.getAddress()

        def serverFunc():
            try:
                s.serve()
                s.close()
            except Exception as e:
                q.put(e)

        def clientFunc():
            try:
                cs = socket.create_connection(a)
                cp = messaging.S5BaseProtocol(cs)

                m = messaging.Message.Ping()
                cp.sendMessage(m)
                m = cp.receiveMessage(messaging.Message.SError)
                self.assertEqual(m.getCode(), "BadMessage")

            except Exception as e:
                q.put(e)
            finally:
                cp.close()

        st = threading.Thread(target=serverFunc)
        st.start()
        ct = threading.Thread(target=clientFunc)
        ct.start()

        ct.join()
        s.shutdown()
        st.join()

        x = None
        while True:
            try:
                e = q.get(False)
                raise e from x
            except queue.Empty:
                break
            except BaseException as e:
                x = e
        if x is not None:
            raise x
