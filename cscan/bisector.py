# Copyright (c) 2015 Hubert Kario <hkario@redhat.com>
# Released under Mozilla Public License Version 2.0

"""Find an itolerance through bisecting Client Hello"""

import copy
from tlslite.extensions import PaddingExtension, TLSExtension
from tlslite.constants import ExtensionType

def list_union(first, second):
    """Return an union between two lists, preserving order"""
    first_i = iter(first)
    second_i = iter(second)
    first_s = set(first)
    second_s = set(second)

    ret = []
    first_el = next(first_i, None)
    second_el = next(second_i, None)
    while first_el is not None and second_el is not None:
        if first_el != second_el:
            if first_el in second_s and second_el in first_s:
                # the second list is longer, so take from it
                ret.append(second_el)
                # no discard as we would have duplicates
                second_el = next(second_i, None)
                continue
            if first_el not in second_s:
                ret.append(first_el)
                first_s.discard(first_el)
                first_el = next(first_i, None)
            if second_el not in first_s:
                ret.append(second_el)
                second_s.discard(second_el)
                second_el = next(second_i, None)
        else:
            ret.append(first_el)
            first_s.discard(first_el)
            second_s.discard(first_el)
            first_el = next(first_i, None)
            second_el = next(second_i, None)
    while first_el:
        if first_el not in second_s:
            ret.append(first_el)
        first_el = next(first_i, None)
    while second_el:
        if second_el not in first_s:
            ret.append(second_el)
        second_el = next(second_i, None)
    return ret


def bisect_lists(first, second):
    """Return a list that is in the "middle" between the given ones"""
    # handle None special cases
    if first is None and second is None:
        return None
    if first is not None and second is None:
        first, second = second, first
    if first is None and second is not None:
        if len(second) == 0:
            return None
        elif len(second) == 1:
            return []
        else:
            first = []
    # make the second lists always the longer one
    if len(first) > len(second):
        second, first = first, second
    first_s = set(first)
    second_s = set(second)
    union = list_union(first, second)
    symmetric_diff = first_s.symmetric_difference(second_s)
    # preserve order for the difference
    symmetric_diff = [x for x in union if x in symmetric_diff]
    half_diff = set(symmetric_diff[:len(symmetric_diff)//2])
    intersection = first_s & second_s

    return [x for x in union if x in half_diff or x in intersection]


def bisect_padding_extension(first, second):
    # skip if undefined
    if first is None and second is None:
        return None
    # if one undefined, make it the first one
    if first is not None and second is None:
        first, second = second, first
    # if first undefined and second has data, make the simplest change
    if first is None and second is not None:
        if len(second.paddingData) == 0:
            return None
        first = PaddingExtension()
    # if both have data, bisect the data
    return PaddingExtension().create((len(first.paddingData) +
                                      len(second.paddingData)) // 2)


def bisect_ext_84(first, second):
    if first is None and second is None:
        return None
    if first is not None and second is None:
        first, second = second, first
    if first is None and second is not None:
        if len(second.extData) == 0:
            return None
        first = TLSExtension(extType=84)
    return TLSExtension(extType=84).create(bytearray((len(first.extData) +
                                           len(second.extData)) // 2))


def replace_ext(ext_list, ext, ext_id):
    """Find, replace or remove extension of ext_id in ext_list"""
    # if the extension to replace is missing, remove it from list
    if ext is None:
        ext_list[:] = [i for i in ext_list if i.extType != ext_id]
        return ext_list
    # if extension type is already present in list, replace it
    for pos, val in enumerate(ext_list):
        if val.extType == ext_id:
            ext_list[pos] = ext
            break
    else:
    # if not, add it to list
        ext_list.append(ext)
    return ext_list


def bisect_extensions(first, second):
    # handle padding extension
    if first is None and second is None:
        return None
    if first is not None and second is None:
        first, second = second, first
    if first is None and second is not None:
        if len(second) == 0:
            return None
        if len(second) == 1:
            return []
        first = []
    f_ext = next((x for x in first if isinstance(x, PaddingExtension)), None)
    s_ext = next((x for x in second if isinstance(x, PaddingExtension)), None)

    if s_ext is not None:
        ext = bisect_padding_extension(f_ext, s_ext)
        if ext != f_ext:
            # we need to return as soon as the first tweakable extension is
            # found as the bisect_lists will duplicate the first extension
            # when there are extensions that are different
            return replace_ext(first[:], ext, ExtensionType.client_hello_padding)

    f_ext = next((x for x in first if x.extType == 84), None)
    s_ext = next((x for x in second if x.extType == 84), None)

    ext = bisect_ext_84(f_ext, s_ext)
    return replace_ext(first[:], ext, 84)


def bisect_hellos(first, second):
    """Return a client hello that is in the "middle" of two other"""
    ret = copy.copy(first)

    ret.client_version = ((first.client_version[0] + second.client_version[0])
                          // 2,
                          (first.client_version[1] + second.client_version[1])
                          // 2)
    ret.cipher_suites = bisect_lists(first.cipher_suites, second.cipher_suites)
    # todo: make it more intelligent, it doesn't handle the case of
    # two extension types each with different payloads for first and second
    ret.extensions = bisect_lists(first.extensions, second.extensions)
    ret.compression_methods = bisect_lists(first.compression_methods,
                                           second.compression_methods)
    f_ext_ids = [i.extType for i in first.extensions] \
            if first.extensions else []
    s_ext_ids = [i.extType for i in second.extensions] \
            if second.extensions else []
    r_ext_ids = [i.extType for i in ret.extensions] \
            if ret.extensions else []
    if f_ext_ids == r_ext_ids or s_ext_ids == r_ext_ids:
        ret.extensions = bisect_extensions(first.extensions,
                                           second.extensions)
    # todo: if there are just single step changes (like version from (3, 1) to
    # (3, 2) and presence and absence of single extension, pick one of those
    # changes as pick the one from the *second* list
    # (as currently always the value from first is selected)
    return ret

class Bisect(object):
    """
    Perform a bisection between two Client Hello's to find intolerance

    Tries to find a cause for intolerance by using a bisection-like
    algorithm
    """

    def __init__(self, good, bad, hostname, callback):
        """Set the generators for good and bad hello's and callback to test"""
        self.good = good
        self.bad = bad
        if hostname is not None:
            self.hostname = bytearray(hostname, 'utf-8')
        else:
            self.hostname = None
        self.callback = callback

    def run(self):
        good_hello = self.good(self.hostname)
        bad_hello = self.bad(self.hostname)
        middle = bisect_hellos(good_hello, bad_hello)

        while good_hello != middle and \
                middle != bad_hello:
            if self.callback(middle):
                good_hello = middle
            else:
                bad_hello = middle
            middle = bisect_hellos(good_hello, bad_hello)

        return (good_hello, bad_hello)
