from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy_server as proxy


class StopAccept(BaseException):
    pass


class ProxyConnectionOwnershipTests(unittest.TestCase):
    def test_delayed_threads_keep_their_own_accepted_socket(self):
        first, second = Mock(), Mock()
        peers = [('127.0.0.1', 10001), ('127.0.0.1', 10002)]
        server = Mock()
        server.accept.side_effect = [(first, peers[0]), (second, peers[1]), StopAccept()]
        pending = []
        semaphore = threading.BoundedSemaphore(2)

        def queue_thread(*, target, daemon):
            self.assertTrue(daemon)
            return Mock(start=lambda: pending.append(target))

        with patch.object(proxy.socket, 'socket', return_value=server), \
             patch.object(proxy.threading, 'Thread', side_effect=queue_thread), \
             patch.object(proxy, 'proxy_connection_sem', semaphore), \
             patch.object(proxy, 'proxy_client') as handle:
            with self.assertRaises(StopAccept):
                proxy.start_proxy_server('127.0.0.1', 1080)
            self.assertEqual(len(pending), 2)
            self.assertFalse(semaphore.acquire(blocking=False))
            for worker in pending:
                worker()
            self.assertEqual(handle.call_args_list, [call(first, peers[0]), call(second, peers[1])])
            self.assertTrue(semaphore.acquire(blocking=False))
            self.assertTrue(semaphore.acquire(blocking=False))
            self.assertFalse(semaphore.acquire(blocking=False))

    def test_failed_handler_releases_connection_slot(self):
        peer = Mock()
        server = Mock()
        server.accept.side_effect = [(peer, ('127.0.0.1', 10003)), StopAccept()]
        pending = []
        semaphore = threading.BoundedSemaphore(1)
        with patch.object(proxy.socket, 'socket', return_value=server), \
             patch.object(proxy.threading, 'Thread', side_effect=lambda **kw: Mock(start=lambda: pending.append(kw['target']))), \
             patch.object(proxy, 'proxy_connection_sem', semaphore), \
             patch.object(proxy, 'proxy_client', side_effect=RuntimeError('test failure')):
            with self.assertRaises(StopAccept):
                proxy.start_proxy_server('127.0.0.1', 1080)
            with self.assertRaisesRegex(RuntimeError, 'test failure'):
                pending[0]()
            self.assertTrue(semaphore.acquire(blocking=False))


if __name__ == '__main__':
    unittest.main()
