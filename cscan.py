from __future__ import print_function
from tlslite.messagesocket import MessageSocket
from tlslite.defragmenter import Defragmenter
from tlslite.messages import ClientHello, ServerHello, ServerHelloDone, Alert
from tlslite.constants import ContentType, CipherSuite, HandshakeType, \
        ExtensionType, AlertLevel
from tlslite.utils.cryptomath import numberToByteArray
from tlslite.extensions import SNIExtension, TLSExtension
from cscan.messages import Certificate
import socket
import random
import sys
import json

from cscan.scanner import Scanner
from cscan.config import Xmas_tree, IE_6, IE_8_Win_XP, \
        IE_11_Win_7, IE_11_Win_8_1, Firefox_46, Firefox_42, HugeCipherList


def no_sni(generator):
    def ret_fun(hostname, generator=generator.__call__):
        ret = generator(hostname)
        ret.extensions = [i for i in ret.extensions
                          if not isinstance(i, SNIExtension)]
        return ret
    generator.__call__ = ret_fun
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

    def ret_fun(hostname, generator=generator.__call__):
        ret = generator(hostname)
        ret.ssl2 = False
        return ret
    generator.__call__ = ret_fun

    version_name = proto_versions.get(version, None)
    if version_name is None:
        version_name = "{0[0]}.{0[1]}".format(version)
    generator.modifications += ["r/{0}".format(version_name)]
    return generator


def no_extensions(generator):
    """Remove extensions"""

    def ret_fun(hostname, generator=generator.__call__):
        ret = generator(hostname)
        ret.extensions = None
        return ret
    generator.__call__ = ret_fun
    generator.modifications += ["no ext"]
    return generator


def truncate_ciphers_to_size(generator, size):
    """Truncate list of ciphers until client hello is no bigger than size"""

    def ret_fun(hostname, generator=generator.__call__, size=size):
        ret = generator(hostname)
        while len(ret.write()) > size:
            ret.cipher_suites.pop()
        return ret
    generator.__call__ = ret_fun
    generator.modifications += ["trunc {0}".format(size)]
    return generator


def scan_with_config(host, port, conf, hostname, __sentry=None, __cache={}):
    assert __sentry is None
    key = (host, port, conf, hostname)
    if key in __cache:
        return __cache[key]

    scanner = Scanner(conf, host, port, hostname)
    ret = scanner.scan()
    __cache[key] = ret
    return ret


class IE_6_ext_tls_1_0(IE_6):
    def __init__(self):
        super(IE_6_ext_tls_1_0, self).__init__()
        self.modifications += ["TLSv1.0", "ext"]
        self.version = (3, 1)
        self.record_version = (3, 0)

    def __call__(self, hostname):
        ret = super(IE_6_ext_tls_1_0, self).__call__(hostname)
        ret.ssl2 = False
        # filter out SSLv2 ciphersuites
        ret.cipher_suites = [i for i in ret.cipher_suites if i <= 0xffff and
                             i != CipherSuite.
                             TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ret.extensions = [TLSExtension(extType=ExtensionType.
                                       renegotiation_info)
                          .create(bytearray(1))]
        return ret


def simple_inspector(result):
    if any(isinstance(x, ServerHelloDone) for x in result):
        ch = next((x for x in result if isinstance(x, ClientHello)), None)
        sh = next((x for x in result if isinstance(x, ServerHello)), None)
        if ch and sh:
            if sh.cipher_suite not in ch.cipher_suites:
                # FAILURE cipher suite mismatch
                return False
            return True
    # incomplete response or error
    return False


def verbose_inspector(desc, result):
    ret = "{0}:".format(desc)
    if any(isinstance(x, ServerHelloDone) for x in result):
        ch = next((x for x in result if isinstance(x, ClientHello)), None)
        sh = next((x for x in result if isinstance(x, ServerHello)), None)
        if sh and ch:
            if sh.cipher_suite not in ch.cipher_suites:
                ret += " FAILURE cipher suite mismatch"
                return ret
            name = CipherSuite.ietfNames[sh.cipher_suite] \
                   if sh.cipher_suite in CipherSuite.ietfNames \
                   else hex(sh.cipher_suite)
            ret += " OK: {0}, {1}".format(sh.server_version,
                                          name)
            return ret
    ret += " FAILURE "
    errors = []
    for msg in result:
        if isinstance(msg, ClientHello):
            continue
        # check if returned message supports custom formatting
        if msg.__class__.__format__ is not object.__format__:
            errors += ["{:vxm}".format(msg)]
        else:
            errors += [repr(msg)]
        # skip printing close errors after fatal alerts, they are expected
        if isinstance(msg, Alert) and msg.level == AlertLevel.fatal:
            break
    ret += "\n".join(errors)
    return ret


def scan_TLS_intolerancies(host, port, hostname):
    configs = {}

    gen = Xmas_tree()
    configs[gen.name] = gen

    gen = set_hello_version(Xmas_tree(), (3, 5))
    configs[gen.name] = gen

    gen = no_sni(Xmas_tree())
    configs[gen.name] = gen

    gen = set_record_version(Xmas_tree(), (3, 3))
    gen = set_hello_version(gen, (3, 3))
    configs[gen.name] = gen

    gen = set_hello_version(Xmas_tree(), (3, 2))
    gen = set_record_version(gen, (3, 2))
    configs[gen.name] = gen

    gen = set_hello_version(Xmas_tree(), (3, 254))
    gen = set_record_version(gen, (3, 3))
    configs[gen.name] = gen

    gen = Firefox_42()
    configs[gen.name] = gen

    gen = no_extensions(Firefox_42())
    configs[gen.name] = gen

    gen = set_hello_version(Firefox_42(), (3, 2))
    configs[gen.name] = gen

    gen = set_hello_version(Firefox_42(), (3, 4))
    configs[gen.name] = gen

    gen = Firefox_46()
    configs[gen.name] = gen

    gen = set_hello_version(Firefox_46(), (3, 254))
    configs[gen.name] = gen

    gen = set_hello_version(Firefox_46(), (3, 5))
    configs[gen.name] = gen

    gen = IE_6()
    configs[gen.name] = gen

    gen = IE_6_ext_tls_1_0()
    configs[gen.name] = gen

    gen = IE_8_Win_XP()
    configs[gen.name] = gen

    gen = set_hello_version(IE_8_Win_XP(), (3, 2))
    configs[gen.name] = gen

    gen = set_hello_version(IE_8_Win_XP(), (3, 4))
    configs[gen.name] = gen

    gen = IE_11_Win_7()
    configs[gen.name] = gen

    gen = set_hello_version(IE_11_Win_7(), (3, 2))
    configs[gen.name] = gen

    gen = no_extensions(IE_11_Win_7())
    configs[gen.name] = gen

    gen = no_sni(IE_11_Win_7())
    configs[gen.name] = gen

    gen = set_hello_version(no_sni(IE_11_Win_7()), (3, 2))
    configs[gen.name] = gen

    gen = set_hello_version(IE_11_Win_7(), (3, 5))
    configs[gen.name] = gen

    gen = set_hello_version(IE_11_Win_7(), (3, 254))
    configs[gen.name] = gen

    gen = IE_11_Win_8_1()
    configs[gen.name] = gen

    gen = set_hello_version(IE_11_Win_8_1(), (3, 4))
    configs[gen.name] = gen

    gen = HugeCipherList()
    configs[gen.name] = gen

    gen = truncate_ciphers_to_size(HugeCipherList(), 16388)
    configs[gen.name] = gen

    results = {}
    for desc, conf in configs.items():
        results[desc] = scan_with_config(host, port, conf, hostname)

    host_up = any(simple_inspector(res) for res in results.values())

    if False:
        for desc, ret in results.items():
            print(verbose_inspector(desc, ret))

    intolerancies = {}
    if not host_up:
        print(json.dumps(intolerancies))
        return

    intolerancies["SSL 3.254"] = all(name in results and
                                     not simple_inspector(results[name])
                                         for name, conf in configs.items()
                                         if conf.version == (3, 254))
    intolerancies["TLS 1.4"] = all(name in results and
                                   not simple_inspector(results[name])
                                   for name, conf in configs.items()
                                   if conf.version == (3, 5))
    intolerancies["TLS 1.3"] = all(name in results and
                                   not simple_inspector(results[name])
                                   for name, conf in configs.items()
                                   if conf.version == (3, 4))
    intolerancies["TLS 1.2"] = all(name in results and
                                   not simple_inspector(results[name])
                                   for name, conf in configs.items()
                                   if conf.version == (3, 3))
    intolerancies["TLS 1.1"] = all(name in results and
                                   not simple_inspector(results[name])
                                   for name, conf in configs.items()
                                   if conf.version == (3, 2))
    intolerancies["TLS 1.0"] = all(name in results and
                                   not simple_inspector(results[name])
                                   for name, conf in configs.items()
                                   if conf.version == (3, 1))
    # intolerancies["Xmas tree"] = not simple_inspector(results["Xmas tree"])
    # intolerancies["Huge Cipher List"] = not simple_inspector(
    #         results["Huge Cipher List"])
    # intolerancies["Huge Cipher List (trunc 16388)"] = not simple_inspector(
    #         results["Huge Cipher List (trunc 16388)"])

    print(json.dumps(intolerancies))

if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise TypeError("Provide IP[:port] and optionally a hostname")
    hostname = None
    if len(sys.argv) == 3:
        hostname = sys.argv[2]
    hostaddr = sys.argv[1].split(":")
    if len(hostaddr) > 1:
        host, port = hostaddr
    else:
        host = hostaddr[0]
        port = 443
    scan_TLS_intolerancies(host, port, hostname)
