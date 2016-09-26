# Copyright (c) 2016 Hubert Kario
# Released under Mozilla Public License 2.0
"""Methods for modifying the scan configurations on the fly."""

from __future__ import print_function
from cscan.constants import CipherSuite, ExtensionType, HashAlgorithm, \
        SignatureAlgorithm
from tlslite.extensions import SNIExtension, PaddingExtension, TLSExtension
from tlslite.constants import GroupName
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
            # do not overflow the length of ciphers
            if len(client_hello.cipher_suites) + ciphers_to_add > 0xfffe // 2:
                ciphers_to_add = 0xfffe // 2 - len(client_hello.cipher_suites)
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


def ext_id_to_short_name(ext_type):
    if ext_type == ExtensionType.server_name:  # 0
        return "SNI"
    elif ext_type == ExtensionType.status_request:  # 5
        return "OCSP staple"
    elif ext_type == ExtensionType.signature_algorithms:  # 13
        return "SigAlgs"
    elif ext_type == ExtensionType.alpn:  # 16
        return "ALPN"
    elif ext_type == ExtensionType.client_hello_padding:  # 21
        return "padding"
    elif ext_type == ExtensionType.encrypt_then_mac:  # 22
        return "EtM"
    elif ext_type == ExtensionType.extended_master_secret:  # 23
        return "EMS"
    elif ext_type == ExtensionType.supports_npn:  # 13172
        return "NPN"
    # early assignments for TLSv1.3
    elif ext_type == ExtensionType.pre_shared_key:  # 41
        return "PSK"
    elif ext_type == ExtensionType.key_share:  # 42
        return "key share"
    else:
        return "ext #{0}".format(ext_type)


def leave_only_ext(generator, ext_type):
    if not generator.extensions:
        return generator
    new_ext = [i for i in generator.extensions if i.extType == ext_type]
    if not new_ext:
        return generator
    generator.extensions[:] = new_ext
    ext_name = ext_id_to_short_name(ext_type)
    generator.modifications += ["only {0}".format(ext_name)]
    return generator


def add_empty_ext(generator, ext_type):
    if generator.extensions is None:
        generator.extensions = []
    if any(i.extType == ext_type for i in generator.extensions):
        return generator
    if ext_type == ExtensionType.client_hello_padding:
        ext = PaddingExtension()
    else:
        ext = TLSExtension(extType=ext_type)
    generator.extensions += [ext]
    ext_name = ext_id_to_short_name(ext_type)
    generator.modifications += ["add {0}".format(ext_name)]
    return generator

def no_empty_last_ext(generator):
    """Reshuffle or add extensions so the last ext is not empty"""
    exts = generator.extensions
    if not exts:
        return generator

    # make sure we have at least one non-zero extension
    if all(len(i.extData) == 0 for i in exts):
        generator = add_one_to_pad_extension(generator)
        exts = generator.extensions

    # and place it last (if it's not done already)
    if not exts[-1].extData:
        non_zero_ext = next(i for i in exts if i.extData)
        exts.remove(non_zero_ext)
        exts.append(non_zero_ext)
        generator.modifications += ["no empty last ext"]

    return generator

def extra_sig_algs(generator):
    """Add undefined signature algorithms"""
    exts = generator.extensions
    if not exts or generator.version < (3, 3):
        return generator

    ext = next((i for i in exts
                if i.extType == ExtensionType.signature_algorithms), None)
    if not ext:
        return generator

    present = set(ext.sigalgs)

    to_add = list(i for i
                  in [(HashAlgorithm.none, SignatureAlgorithm.ecdsa),
                      (HashAlgorithm.none, 4),
                      (HashAlgorithm.sha256, 4),
                      (7, SignatureAlgorithm.anonymous),
                      (7, SignatureAlgorithm.ecdsa),
                      (7, 4)]
                  if i not in present)
    ext.sigalgs[:] = to_add + ext.sigalgs

    generator.modifications += ["more sigalgs"]
    return generator

def extra_groups(generator):
    """Add more curves/groups to curves_extensions"""
    exts = generator.extensions
    if not exts:
        return generator

    ext = next((i for i in exts
                if i.extType == ExtensionType.supported_groups), None)
    if not ext:
        return generator

    present = set(ext.groups)

    to_add = list(i for i in
                  itertools.chain(GroupName.allFF,
                                  [GroupName.brainpoolP256r1,
                                   GroupName.brainpoolP384r1,
                                   GroupName.brainpoolP512r1],
                                  [0xcaca, 0xdada])
                  if i not in present)
    ext.groups[:] = to_add + ext.groups
    generator.modifications += ["more groups"]
    return generator

def add_compressions_to_number(generator, num):
    """Add compression methods to hello"""
    compress_to_add = num - len(generator.compression_methods)
    if compress_to_add <= 0:
        return generator
    present = set(generator.compression_methods)
    generator.compression_methods.extend(itertools.islice((i for i in
                                                           range(0, 256)
                                                           if i not in
                                                           present),
                                                          compress_to_add))

    generator.modifications += ["more comp mthds"]
    return generator
