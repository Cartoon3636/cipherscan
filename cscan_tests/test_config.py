# Copyright (c) 2015 Hubert Kario
# Released under Mozilla Public License Version 2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.messages import ClientHello
from tlslite.utils.codec import Parser
from cscan.config import firefox_42, xmas_tree_tls_1_3

class TestFirefox(unittest.TestCase):
    def test_firefox_42(self):
        ch = firefox_42(bytearray(b'example.com'))

        self.assertIsNotNone(ch)
        self.assertIsInstance(ch, ClientHello)
        self.assertEqual(len(ch.write()), 176)

class TestXmasTree(unittest.TestCase):
    def test_xmas_tree_tls_1_3(self):
        ch = xmas_tree_tls_1_3(bytearray(b'example.com'))

        self.assertIsNotNone(ch)
        self.assertIsInstance(ch, ClientHello)
        self.assertEqual(len(ch.write()), 1586)

    def test_xmas_tree_tls_1_3_parse(self):
        ch = xmas_tree_tls_1_3(bytearray(b'example.com'))

        parser = Parser(ch.write()[1:])

        client_hello = ClientHello()
        client_hello.parse(parser)


if __name__ == "__main__":
    unittest.main()
