# Copyright (c) 2016 Hubert Kario
# Released under Mozilla Public License 2.0
"""Methods for modifying the scan configurations on the fly."""

from __future__ import print_function
from tlslite.constants import CipherSuite, ExtensionType
from tlslite.extensions import SNIExtension, PaddingExtension, TLSExtension
import itertools


def no_sni(generator):
    if not generator.extensions:
        return generator
    generator.extensions[:] = (x for x in generator.extensions
                               if not isinstance(x, SNIExtension))
    generator.modifications.append("no SNI")
    return generator


proto_versions = {(3, 0): "SSLv3",
                  (3, 1): "TLSv1.0",
                  (3, 2): "TLSv1.1",
                  (3, 3): "TLSv1.2",
                  (3, 4): "TLSv1.3",
                  (3, 5): "TLSv1.4",
                  (3, 6): "TLSv1.5"}


def version_to_str(version):
    """Convert a version tuple to human-readable string."""
    version_name = proto_versions.get(version, None)
    if version_name is None:
        version_name = "{0[0]}.{0[1]}".format(version)
    return version_name


def set_hello_version(generator, version):
    """Set client hello version."""
    generator.version = version
    generator.modifications += [version_to_str(version)]
    return generator


def set_record_version(generator, version):
    """Set record version, un-SSLv2-ify"""

    generator.record_version = version
    generator.ciphers[:] = (i for i in generator.ciphers if i <= 0xffff)
    generator.ssl2 = False
    generator.modifications += ["r/{0}".format(version_to_str(version))]
    return generator


def no_extensions(generator):
    """Remove extensions"""

    generator.extensions = None
    generator.modifications += ["no ext"]
    return generator


def add_one_to_pad_extension(generator):
    """If not present add padding extension, make it one byte longer"""

    if generator.extensions is None:
        generator.extensions = []
    padd_ext = next((i for i in generator.extensions
                     if i.extType == ExtensionType.client_hello_padding), None)
    if not padd_ext:
        padd_ext = PaddingExtension()
        generator.extensions.append(padd_ext)
    padd_ext.paddingData += bytearray(1)

    generator.modifications += ["pad +1"]
    return generator


def divceil(divident, divisor):
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))


def truncate_ciphers_to_size(generator, size):
    """Truncate list of ciphers until client hello is no bigger than size"""

    def cb_fun(client_hello, size=size):
        hello_len = len(client_hello.write())
        bytes_to_remove = hello_len - size
        if bytes_to_remove > 0:
            ciphers_to_remove = divceil(bytes_to_remove, 2)
            client_hello.cipher_suites[:] = \
                    client_hello.cipher_suites[:-ciphers_to_remove]
        return client_hello

    generator.callbacks.append(cb_fun)
    generator.modifications += ["trunc c/{0}".format(size)]
    return generator


def append_ciphers_to_size(generator, size):
    """
    Add ciphers from the 0x2000-0xa000 range until size is reached

    Increases the size of the Client Hello message until it is at least
    `size` bytes long. Uses cipher ID's from the 0x2000-0xc000 range to do
    it (0x5600, a.k.a TLS_FALLBACK_SCSV, excluded)
    """

    def cb_fun(client_hello, size=size):
        ciphers_iter = iter(range(0x2000, 0xc000))
        ciphers_present = set(client_hello.cipher_suites)
        # we don't want to add a cipher id with special meaning
        # and the set is used only internally
        ciphers_present.add(CipherSuite.TLS_FALLBACK_SCSV)

        bytes_to_add = size - len(client_hello.write())
        if bytes_to_add > 0:
            ciphers_to_add = divceil(bytes_to_add, 2)
            ciphers_gen = (x for x in ciphers_iter
                           if x not in ciphers_present)
            client_hello.cipher_suites.extend(itertools.islice(ciphers_gen,
                                                               ciphers_to_add))
        return client_hello
    generator.callbacks.append(cb_fun)
    generator.modifications += ["append c/{0}".format(size)]
    return generator


def append_ciphers_to_number(generator, number):
    """
    Create hello with number ciphers using ciphers from 0x2000-0xa000 range

    Increases the size of Client Hello by adding ciphers until there are
    at least number ciphers in hello
    """
    ciphers_iter = iter(range(0x2000, 0xc000))
    ciphers_present = set(generator.ciphers)
    ciphers_present.add(CipherSuite.TLS_FALLBACK_SCSV)

    ciphers_to_add = number - len(generator.ciphers)
    if ciphers_to_add > 0:
        ciphers_gen = (i for i in ciphers_iter
                       if i not in ciphers_present)
        generator.ciphers.extend(itertools.islice(ciphers_gen,
                                                  ciphers_to_add))
    generator.modifications += ["ciphers {0}".format(ciphers_to_add)]
    return generator


def extend_with_ext_to_size(generator, size,
                            ext_type=ExtensionType.client_hello_padding):
    """
    Add the padding extension so that the Hello is at least `size` bytes

    Either adds a padding extension or extends an existing one so that
    the specified size is reached
    """

    def cb_fun(client_hello, size=size):
        if len(client_hello.write()) > size:
            return client_hello
        if not client_hello.extensions:
            client_hello.extensions = []
        ext = next((x for x in client_hello.extensions
                    if x.extType == ext_type), None)
        if ext_type == ExtensionType.client_hello_padding:
            if not ext:
                ext = PaddingExtension()
                client_hello.extensions.append(ext)
            # check if just adding the extension, with no payload, haven't pushed
            # us over the limit
            bytes_to_add = size - len(client_hello.write())
            if bytes_to_add > 0:
                ext.paddingData += bytearray(bytes_to_add)
            return client_hello
        else:
            if not ext:
                ext = TLSExtension(extType=ext_type)
                client_hello.extensions.append(ext)
            # check if just adding the extension, with no payload, haven't pushed
            # us over the limit
            bytes_to_add = size - len(client_hello.write())
            if bytes_to_add > 0:
                ext.create(bytearray(len(ext.extData) + bytes_to_add))
            return client_hello
    generator.callbacks.append(cb_fun)
    generator.modifications += ["append e/{0}".format(size)]
    return generator


def set_extensions_to_size(generator, size):
    """
    Set extensions length to size, add padding extension if missing

    Extend only the extensions field in Client Hello, so that it is `size`
    bytes long. Adds padding extension if it's missing, extends it if it
    is already present
    """

    def cb_fun(client_hello, size=size):
        if not client_hello.extensions:
            client_hello.extensions = []
        ext = next((i for i in client_hello.extensions
                    if i.extType == ExtensionType.client_hello_padding), None)
        extensions_size = sum(len(i.write()) for i in client_hello.extensions)
        bytes_to_add = size - extensions_size
        if bytes_to_add <= 0:
            return client_hello
        # can't add through single extension less than 4 bytes
        if bytes_to_add < 4 and not ext:
            return client_hello
        if not ext:
            ext = PaddingExtension()
            client_hello.extensions.append(ext)
            bytes_to_add -= 4  # extension header
        ext.paddingData += bytearray(bytes_to_add)
        return client_hello
    generator.callbacks.append(cb_fun)
    generator.modifications += ["size ext {0}".format(size)]
    return generator


def add_empty_ext(generator, ext_type):
    if generator.extensions is None:
        generator.extensions = []
    generator.extensions += [TLSExtension(extType=ext_type)
                             .create(bytearray(0))]
    generator.modifications += ["add ext {0}".format(ext_type)]
    return generator
