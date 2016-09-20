# Copyright (c) 2015 Hubert Kario
# Released under Mozilla Public License Version 2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from cscan.config import Xmas_tree, Firefox_42
from cscan.modifiers import truncate_ciphers_to_size, append_ciphers_to_size, \
        extend_with_ext_to_size, append_ciphers_to_number, \
        set_extensions_to_size

class TestTruncateCiphersToSize(unittest.TestCase):
    def test_with_big_hello(self):
        gen = Xmas_tree()

        self.assertEqual(len(gen(b'localhost').write()), 2800)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49196)

        gen = truncate_ciphers_to_size(gen, 2780)

        self.assertEqual(len(gen(b'localhost').write()), 2780)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49196)


class TestAppendCiphersToSize(unittest.TestCase):
    def test_with_small_hello(self):
        gen = Firefox_42()

        self.assertLess(len(gen(b'localhost').write()), 2**10)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49195)

        gen = append_ciphers_to_size(gen, 2**12)

        self.assertEqual(len(gen(b'localhost').write()), 2**12)
        self.assertEqual(gen(b'localhost').cipher_suites[0], 49195)


class TestAppendCiphersToNumber(unittest.TestCase):
    def test_with_small_hello(self):
        gen = Firefox_42()

        self.assertEqual(len(gen.ciphers), 11)

        gen = append_ciphers_to_number(gen, 0xfffe//2)

        self.assertEqual(len(gen.ciphers), 0xfffe//2)


class TestExtendWithExtToSize(unittest.TestCase):
    def test_with_small_hello(self):
        gen = Firefox_42()

        self.assertLess(len(gen(b'localhost').write()), 2**10)

        gen = extend_with_ext_to_size(gen, 2**12)

        self.assertEqual(len(gen(b'localhost').write()), 2**12)


class TestSetExtensionsToSize(unittest.TestCase):
    def test_with_small_hello(self):
        gen = Firefox_42()

        self.assertEqual(len(gen(b'localhost').write()), 178)

        gen = set_extensions_to_size(gen, 0xffff)

        self.assertEqual(len(gen(b'localhost').write()), 65602)

        gen = set_extensions_to_size(Firefox_42(), 0xffff)

        self.assertEqual(len(gen(b'example.com').write()), 65602)
