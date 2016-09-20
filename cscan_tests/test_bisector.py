# Copyright (c) 2015 Hubert Kario
# Released under Mozilla Public License Version 2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import copy

from tlslite.extensions import SignatureAlgorithmsExtension, SNIExtension, \
        SupportedGroupsExtension, ECPointFormatsExtension, TLSExtension
from cscan.config import VeryCompatible, IE_8_Win_XP, Xmas_tree
from cscan.bisector import bisect_lists, list_union, Bisect, replace_ext
from cscan.modifiers import extend_with_ext_to_size, append_ciphers_to_size

class TestListUnion(unittest.TestCase):
    def test_identical(self):
        a = [1, 2, 3, 4]
        b = [1, 2, 3, 4]
        c = list_union(a, b)
        self.assertEqual(c, [1, 2, 3, 4])

    def test_extended(self):
        a = [1, 2, 3, 4]
        b = [1, 2, 3, 4, 5, 6, 7, 8]
        c = list_union(a, b)
        self.assertEqual(c, [1, 2, 3, 4, 5, 6, 7, 8])

    def test_extended_reversed(self):
        a = [1, 2, 3, 4, 5, 6, 7, 8]
        b = [1, 2, 3, 4]
        c = list_union(a, b)
        self.assertEqual(c, [1, 2, 3, 4, 5, 6, 7, 8])

    def test_prepended(self):
        a = [5, 6, 7, 8]
        b = [1, 2, 3, 4, 5, 6, 7, 8]
        c = list_union(a, b)
        self.assertEqual(c, [1, 2, 3, 4, 5, 6, 7, 8])

    def test_mixed(self):
        a = [1, 2, 3, 4]
        b = [5, 1, 2, 6, 4]
        c = list_union(a, b)
        self.assertEqual(c, [5, 1, 2, 3, 6, 4])

    def test_mixed_reversed(self):
        a = [5, 1, 2, 6, 4]
        b = [1, 2, 3, 4]
        c = list_union(a, b)
        self.assertEqual(c, [5, 1, 2, 6, 3, 4])

    def test_different_order(self):
        a = [1, 2, 3, 4]
        b = [2, 3, 1, 4]
        c = list_union(a, b)
        self.assertEqual(c, [2, 3, 1, 4])

    def test_different_order2(self):
        a = [1, 2, 3, 4, 5, 6]
        b = [3, 1, 4, 2, 5, 6]
        c = list_union(a, b)
        self.assertEqual(c, [3, 1, 4, 2, 5, 6])

    def test_different_order_superset(self):
        a = [1, 2, 3, 4]
        b = [4, 3, 1, 2, 5, 6]
        c = list_union(a, b)
        self.assertEqual(c, [4, 3, 1, 2, 5, 6])

    def test_completely_disjoint(self):
        a = [1, 2, 3, 4]
        b = [5, 6, 7, 8]
        c = list_union(a, b)
        self.assertEqual(c, [1, 5, 2, 6, 3, 7, 4, 8])

    def test_different_suffix(self):
        a = [1, 2, 3, 4]
        b = [1, 2, 5, 6]
        c = list_union(a, b)
        self.assertEqual(c, [1, 2, 3, 5, 4, 6])

    def test_different_prefix(self):
        a = [1, 2, 3, 4]
        b = [5, 6, 3, 4]
        c = list_union(a, b)
        self.assertEqual(c, [1, 5, 2, 6, 3, 4])

    def test_one_empty(self):
        a = [1, 2, 3, 4]
        b = []
        c = list_union(a, b)
        self.assertEqual(c, [1, 2, 3, 4])

    def test_both_empty(self):
        a = []
        b = []
        c = list_union(a, b)
        self.assertEqual(c, [])

class TestBisectLists(unittest.TestCase):
    def test_sorted(self):
        a = [1, 5, 7, 9]
        b = [3, 5, 6, 8]
        c = bisect_lists(a, b)
        self.assertEqual(c, [1, 3, 5, 7])

        d = bisect_lists(c, b)
        self.assertEqual(d, [1, 3, 5, 7])

        e = bisect_lists(a, c)
        self.assertEqual(e, [1, 3, 5, 7])

    def test_extended(self):
        a = [1, 2, 3, 4]
        b = [1, 2, 3, 4, 5, 6, 7, 8]
        c = bisect_lists(a, b)
        self.assertEqual(a, [1, 2, 3, 4])
        self.assertEqual(b, [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual(c, [1, 2, 3, 4, 5, 6])

        d = bisect_lists(c, b)
        self.assertEqual(d, [1, 2, 3, 4, 5, 6, 7])

    def test_extended_reversed(self):
        a = [1, 2, 3, 4, 5, 6, 7, 8]
        b = [1, 2, 3, 4]
        c = bisect_lists(a, b)
        self.assertEqual(a, [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual(b, [1, 2, 3, 4])
        self.assertEqual(c, [1, 2, 3, 4, 5, 6])

    def test_prepended(self):
        a = [5, 6, 7, 8]
        b = [1, 2, 3, 4, 5, 6, 7, 8]
        c = bisect_lists(a, b)
        self.assertEqual(c, [1, 2, 5, 6, 7, 8])

    def test_both_different(self):
        a = [1, 2, 3, 4]
        b = [1, 2, 5, 6]
        c = bisect_lists(a, b)
        self.assertEqual(c, [1, 2, 3, 5])

    def test_small_difference(self):
        a = [1, 2, 3, 4]
        b = [1, 2, 3, 5]
        c = bisect_lists(a, b)
        self.assertEqual(c, [1, 2, 3, 4])

    def test_small_difference_with_different_order(self):
        a = [2, 3, 1, 4]
        b = [1, 2, 3, 5]
        c = bisect_lists(a, b)
        self.assertEqual(c, [1, 2, 3, 5])

    def test_one_empty(self):
        a = []
        b = [1, 2, 3, 4]
        c = bisect_lists(a, b)
        self.assertEqual(c, [1, 2])

    def test_both_empty(self):
        a = []
        b = []
        c = bisect_lists(a, b)
        self.assertEqual(c, [])

    def test_one_None(self):
        a = None
        b = [1, 2, 3, 4]
        c = bisect_lists(a, b)
        self.assertEqual(c, [1, 2])

    def test_short_and_None(self):
        a = None
        b = [1]
        c = bisect_lists(a, b)
        self.assertEqual(c, [])

    def test_empty_and_None(self):
        a = None
        b = []
        c = bisect_lists(a, b)
        self.assertEqual(c, None)

    def test_long_identical(self):
        a = [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21, 22, 23, 84]
        b = [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21, 22, 23, 84]
        c = bisect_lists(a, b)
        self.assertEqual(c,
                [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21, 22, 23,
                 84])

    def test_long_identical_objects(self):
        a = [TLSExtension(extType=i) for i in
             [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21, 22, 23, 84]]
        b = [TLSExtension(extType=i) for i in
             [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21, 22, 23, 84]]
        c = bisect_lists(a, b)
        self.assertEqual([i.extType for i in c],
                         [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21,
                          22, 23, 84])

    def test_long_different_objects(self):
        a = [TLSExtension(extType=i) for i in
             [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21, 22, 23, 84]]
        b = [TLSExtension(extType=i) for i in
             [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21, 22, 23]]
        b += [TLSExtension(extType=84).create(bytearray(1))]
        self.assertNotEqual(a, b)
        c = bisect_lists(a, b)
        self.assertEqual([i.extType for i in c],
                         [0, 65281, 10, 11, 35, 1, 16, 5, 17, 13, 42, 15, 21,
                          22, 23, 84])
        self.assertEqual(c, a)


class TestReplaceExt(unittest.TestCase):
    def test_remove(self):
        a = [TLSExtension(extType=0), TLSExtension(extType=1)]
        replace_ext(a, None, 0)

        self.assertEqual(a, [TLSExtension(extType=1)])

    def test_replace(self):
        a = [TLSExtension(extType=0).create(bytearray(10)),
             TLSExtension(extType=1)]
        replace_ext(a, TLSExtension(extType=0).create(bytearray(20)), 0)

        self.assertEqual(a, [TLSExtension(extType=0).create(bytearray(20)),
                             TLSExtension(extType=1)])

    def test_add(self):
        a = [TLSExtension(extType=1)]
        replace_ext(a, TLSExtension(extType=0).create(bytearray(20)), 0)

        self.assertEqual(a, [TLSExtension(extType=1),
                             TLSExtension(extType=0).create(bytearray(20))])


class TestBisect(unittest.TestCase):
    def test___init__(self):
        b = Bisect(None, None, None, None)
        self.assertIsNotNone(b)

    def test_run(self):
        def test_cb(hello):
            return len(hello.write()) <= 2**14

        bad = append_ciphers_to_size(Xmas_tree(), 2**15)
        good = VeryCompatible()
        self.assertGreater(len(bad(b'localhost').write()), 2**14)
        self.assertLess(len(good(b'localhost').write()), 2**14)

        bi = Bisect(good, bad, "localhost", test_cb)

        a, b = bi.run()

        self.assertEqual(len(a.write()), 2**14-1)
        self.assertEqual(len(b.write()), 2**14+1)

    def test_run_with_extensions(self):
        def test_cb(hello):
            if not hello.extensions:
                return True
            a = next((x for x in hello.extensions
                      if isinstance(x, SignatureAlgorithmsExtension)), None)
            return a is None
        good = IE_8_Win_XP()
        bad = VeryCompatible()

        self.assertTrue(test_cb(good(b'localhost')))
        self.assertFalse(test_cb(bad(b'localhost')))

        bi = Bisect(good, bad, "localhost", test_cb)

        a, b = bi.run()

        ext = next((x for x in a.extensions
                    if isinstance(x, SignatureAlgorithmsExtension)), None) \
              if a.extensions else None
        self.assertIsNone(ext)
        ext = next((x for x in b.extensions
                    if isinstance(x, SignatureAlgorithmsExtension)), None)
        self.assertIsNotNone(ext)

    def test_run_with_extension_size(self):
        def test_cb(hello):
            return len(hello.write()) <= 2**14

        bad = extend_with_ext_to_size(VeryCompatible(), 2**16)
        good = VeryCompatible()

        bi = Bisect(good, bad, "localhost", test_cb)

        a, b = bi.run()

        self.assertEqual(len(a.write()), 2**14)
        self.assertEqual(len(b.write()), 2**14+1)

    def test_run_with_ext_and_ciphers(self):
        def test_cb(hello):
            return len(hello.write()) <= 2**14

        bad = extend_with_ext_to_size(VeryCompatible(), 2**15)
        bad = append_ciphers_to_size(bad, 2**16)
        good = VeryCompatible()

        bi = Bisect(good, bad, "localhost", test_cb)

        a, b = bi.run()

        # the boundary can be found by truncating ciphers, not extensions
        self.assertIn(len(a.write()), (2**14, 2**14 - 1))
        self.assertIn(len(b.write()), (2**14 + 1, 2**14 + 2))

    def test_run_with_ext_and_ciphers_plus_one(self):
        def test_cb(hello):
            return len(hello.write()) <= 2**14 + 1

        bad = extend_with_ext_to_size(VeryCompatible(), 2**15)
        bad = append_ciphers_to_size(bad, 2**16)
        good = VeryCompatible()

        bi = Bisect(good, bad, "localhost", test_cb)

        a, b = bi.run()

        # the boundary can be found by truncating ciphers, not extensions
        self.assertIn(len(a.write()), (2**14 + 1, 2**14))
        self.assertIn(len(b.write()), (2**14 + 2, 2**14 + 3))

    def test_run_with_ext_and_ciphers_plus_two(self):
        def test_cb(hello):
            return len(hello.write()) <= 2**14 + 2

        bad = extend_with_ext_to_size(VeryCompatible(), 2**15)
        bad = append_ciphers_to_size(bad, 2**16)
        good = VeryCompatible()

        bi = Bisect(good, bad, "localhost", test_cb)

        a, b = bi.run()

        # the boundary can be found by truncating ciphers, not extensions
        self.assertIn(len(a.write()), (2**14 + 2, 2**14 + 1))
        self.assertIn(len(b.write()), (2**14 + 3, 2**14 + 4))

    def test_run_with_pad_and_84_ext(self):
        def test_cb(hello):
            return len(hello.write()) <= 2**14

        # Xmas tree has a random key share, so we need to use the exact
        # same object for testing
        good = Xmas_tree()
        bad = extend_with_ext_to_size(copy.deepcopy(good), 2**15, 84)
        self.assertFalse(test_cb(bad(b"localhost")))
        self.assertTrue(test_cb(good(b"localhost")))

        bi = Bisect(good, bad, "localhost", test_cb)

        #import pdb; pdb.set_trace()
        a, b = bi.run()

        self.assertEqual(len(a.write()), 2**14)
        self.assertEqual(len(b.write()), 2**14+1)
