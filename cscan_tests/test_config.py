# Copyright (c) 2015 Hubert Kario
# Released under Mozilla Public License Version 2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.messages import ClientHello
from tlslite.utils.codec import Parser
from cscan.config import Firefox_42, Xmas_tree

class TestFirefox(unittest.TestCase):
    def test_firefox_42(self):
        ch = Firefox_42()(bytearray(b'example.com'))

        self.assertIsNotNone(ch)
        self.assertIsInstance(ch, ClientHello)
        self.assertEqual(len(ch.write()), 176)

class TestXmasTree(unittest.TestCase):
    def test_xmas_tree_tls_1_3(self):
        ch = Xmas_tree()(bytearray(b'example.com'))

        self.assertIsNotNone(ch)
        self.assertIsInstance(ch, ClientHello)
        self.assertEqual(len(ch.write()), 2792)

    def test_xmas_tree_tls_1_3_parse(self):
        ch = Xmas_tree()(bytearray(b'example.com'))

        parser = Parser(ch.write()[1:])

        client_hello = ClientHello()
        client_hello.parse(parser)


if __name__ == "__main__":
    unittest.main()
