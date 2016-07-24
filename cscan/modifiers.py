from __future__ import print_function
from tlslite.constants import CipherSuite
from tlslite.extensions import SNIExtension, PaddingExtension

def patch_call(instance, func):
    class _(type(instance)):
        def __call__(self, *args, **kwargs):
            return func(self, *args, **kwargs)
    instance.__class__ = _


def no_sni(generator):
    def ret_fun(self, hostname):
        ret = super(type(self), self).__call__(hostname)
        ret.extensions = [i for i in ret.extensions
                          if not isinstance(i, SNIExtension)]
        return ret
    patch_call(generator, ret_fun)
    generator.modifications += ["no SNI"]
    return generator

proto_versions = {(3, 0): "SSLv3",
                  (3, 1): "TLSv1.0",
                  (3, 2): "TLSv1.1",
                  (3, 3): "TLSv1.2",
                  (3, 4): "TLSv1.3",
                  (3, 5): "TLSv1.4",
                  (3, 6): "TLSv1.5"}


def set_hello_version(generator, version):
    """Set client hello version"""

    generator.version = version

    version_name = proto_versions.get(version, None)
    if version_name is None:
        version_name = "{0[0]}.{0[1]}".format(version)
    generator.modifications += [version_name]
    return generator


def set_record_version(generator, version):
    """Set record version, un-SSLv2-ify"""

    generator.record_version = version
    generator.ciphers = [i for i in generator.ciphers if i <= 0xffff]

    def ret_fun(self, hostname):
        ret = super(type(self), self).__call__(hostname)
        ret.ssl2 = False
        return ret
    patch_call(generator, ret_fun)

    version_name = proto_versions.get(version, None)
    if version_name is None:
        version_name = "{0[0]}.{0[1]}".format(version)
    generator.modifications += ["r/{0}".format(version_name)]
    return generator


def no_extensions(generator):
    """Remove extensions"""

    def ret_fun(self, hostname):
        ret = super(type(self), self).__call__(hostname)
        ret.extensions = None
        return ret
    patch_call(generator, ret_fun)
    generator.modifications += ["no ext"]
    return generator


def truncate_ciphers_to_size(generator, size):
    """Truncate list of ciphers until client hello is no bigger than size"""

    def ret_fun(self, hostname, size=size):
        ret = super(type(self), self).__call__(hostname)
        while len(ret.write()) > size:
            ret.cipher_suites.pop()
        return ret
    patch_call(generator, ret_fun)
    generator.modifications += ["trunc c/{0}".format(size)]
    return generator


def append_ciphers_to_size(generator, size):
    """
    Add ciphers from the 0x2000-0xa000 range until size is reached

    Increases the size of the Client Hello message until it is at least
    `size` bytes long. Uses cipher ID's from the 0x2000-0xc000 range to do
    it (0x5600, a.k.a TLS_FALLBACK_SCSV, excluded)
    """

    def ret_fun(self, hostname, size=size):
        ret = super(type(self), self).__call__(hostname)
        ciphers_iter = iter(range(0x2000, 0xc000))
        ciphers_present = set(ret.cipher_suites)
        bytes_to_add = size - len(ret.write())
        while bytes_to_add > 0:
            ciph = next(ciphers_iter)
            # don't put ciphers with special meaning or already present
            if ciph == CipherSuite.TLS_FALLBACK_SCSV or \
               ciph in ciphers_present:
                continue
            ciphers_present.add(ciph)
            ret.cipher_suites.append(ciph)
            bytes_to_add -= 2
        return ret
    patch_call(generator, ret_fun)
    generator.modifications += ["append c/{0}".format(size)]
    return generator


def extend_with_ext_to_size(generator, size):
    """
    Add the padding extension so that the Hello is at least `size` bytes

    Either adds a padding extension or extends an existing one so that
    the specified size is reached
    """

    def ret_fun(self, hostname, size=size):
        ret = super(type(self), self).__call__(hostname)
        if len(ret.write()) > size:
            return ret
        if not ret.extensions:
            ret.extensions = []
        ext = next((x for x in ret.extensions
                    if isinstance(x, PaddingExtension)), None)
        if not ext:
            ext = PaddingExtension()
            ret.extensions.append(ext)
        bytes_to_add = size - len(ret.write())
        if bytes_to_add > 0:
            ext.paddingData += bytearray(bytes_to_add)
        return ret
    patch_call(generator, ret_fun)
    generator.modifications += ["append e/{0}".format(size)]
    return generator
