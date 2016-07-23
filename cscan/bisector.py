# Copyright (c) 2015 Hubert Kario <hkario@redhat.com>
# Released under Mozilla Public License Version 2.0

"""Find an itolerance through bisecting Client Hello"""

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
