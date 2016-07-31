from __future__ import print_function
from tlslite.messagesocket import MessageSocket
from tlslite.defragmenter import Defragmenter
from tlslite.messages import ClientHello, ServerHello, ServerHelloDone, Alert
from tlslite.constants import ContentType, CipherSuite, HandshakeType, \
        ExtensionType, AlertLevel
from tlslite.utils.cryptomath import numberToByteArray
from tlslite.extensions import SNIExtension, TLSExtension, PaddingExtension
from cscan.messages import Certificate
import socket
import random
import sys
import json
import getopt

from cscan.scanner import Scanner
from cscan.config import Xmas_tree, IE_6, IE_8_Win_XP, \
        IE_11_Win_7, IE_11_Win_8_1, Firefox_46, Firefox_42, HugeCipherList, \
        VeryCompatible
from cscan.bisector import Bisect
from cscan.modifiers import no_sni, set_hello_version, set_record_version, \
        no_extensions, truncate_ciphers_to_size, append_ciphers_to_size, \
        extend_with_ext_to_size


def scan_with_config(host, port, conf, hostname, __sentry=None, __cache={}):
    assert __sentry is None
    key = (host, port, conf, hostname)
    if key in __cache:
        return __cache[key]

    scanner = Scanner(conf, host, port, hostname)
    ret = scanner.scan()
    __cache[key] = ret
    if verbose and not json_out:
        print(".", end='')
        sys.stdout.flush()
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
            ret += " ok: {0}, {1}".format(sh.server_version,
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

configs = {}

def load_configs():
    base_configs = [Xmas_tree, Firefox_42, IE_8_Win_XP, IE_11_Win_7,
                    VeryCompatible]
    for conf in base_configs:
        # only no extensions
        gen = no_extensions(conf())
        configs[gen.name] = gen

        gen = no_sni(conf())
        configs[gen.name] = gen

        for version in ((3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 254)):
            if conf().version != version:
                # just changed version
                gen = set_hello_version(conf(), version)
                if gen.record_version > version:
                    gen.record_version = version
                configs[gen.name] = gen

                # changed version and no extensions
                gen = set_hello_version(conf(), version)
                if gen.record_version > version:
                    gen.record_version = version
                gen = no_extensions(gen)
                configs[gen.name] = gen

                # changed version and no sni
                gen = set_hello_version(conf(), version)
                if gen.record_version > version:
                    gen.record_version = version
                gen = no_sni(gen)
                configs[gen.name] = gen

    # Xmas tree configs
    gen = Xmas_tree()
    configs[gen.name] = gen

    gen = no_sni(Xmas_tree())
    configs[gen.name] = gen

    # Firefox 42 configs
    gen = Firefox_42()
    configs[gen.name] = gen

    # Firefox 46 configs
    gen = Firefox_46()
    configs[gen.name] = gen

    gen = set_hello_version(Firefox_46(), (3, 254))
    configs[gen.name] = gen

    gen = set_hello_version(Firefox_46(), (3, 5))
    configs[gen.name] = gen

    gen = no_extensions(set_hello_version(Firefox_46(), (3, 5)))
    configs[gen.name] = gen

    gen = set_hello_version(Firefox_46(), (3, 1))
    configs[gen.name] = gen

    # IE 6 configs
    gen = IE_6()
    configs[gen.name] = gen

    gen = IE_6_ext_tls_1_0()
    configs[gen.name] = gen

    # IE 8 configs
    gen = IE_8_Win_XP()
    configs[gen.name] = gen

    # IE 11 on Win 7 configs
    gen = IE_11_Win_7()
    configs[gen.name] = gen

    gen = no_sni(IE_11_Win_7())
    configs[gen.name] = gen

    gen = set_hello_version(no_sni(IE_11_Win_7()), (3, 2))
    configs[gen.name] = gen

    # IE 11 on Win 8.1 configs
    gen = IE_11_Win_8_1()
    configs[gen.name] = gen

    gen = set_hello_version(IE_11_Win_8_1(), (3, 1))
    configs[gen.name] = gen

    gen = set_hello_version(IE_11_Win_8_1(), (3, 4))
    configs[gen.name] = gen

    # Huge Cipher List
    gen = HugeCipherList()
    configs[gen.name] = gen

    gen = truncate_ciphers_to_size(HugeCipherList(), 16388)
    configs[gen.name] = gen

    # Very Compatible
    gen = VeryCompatible()
    configs[gen.name] = gen

    gen = append_ciphers_to_size(VeryCompatible(), 2**16)
    configs[gen.name] = gen

    gen = extend_with_ext_to_size(VeryCompatible(), 2**16)
    configs[gen.name] = gen

    gen = extend_with_ext_to_size(VeryCompatible(), 16388)
    configs[gen.name] = gen

def scan_TLS_intolerancies(host, port, hostname):
    results = {}

    def conf_iterator(predicate):
        """
        Caching, selecting iterator over configs

        Returns an iterator that will go over configs that match the provided
        predicate (a function that returns true or false depending if given
        config is ok for test at hand) while saving the results to the
        cache/verbose `results` log/dictionary
        """
        return (not simple_inspector(results[name] if name in results
                                     else results.setdefault(name,
                                        scan_with_config(host,
                                                         port,
                                                         conf,
                                                         hostname)))
                for name, conf in configs.items()
                if predicate(conf))

    host_up = not all(conf_iterator(lambda conf: True))

    intolerancies = {}
    if not host_up:
        if json_out:
            print(json.dumps(intolerancies))
        else:
            print("Host does not seem to support SSL or TLS protocol")
        return


    intolerancies["SSL 3.254"] = all(conf_iterator(lambda conf:
                                                   conf.version == (3, 254)))
    intolerancies["TLS 1.4"] = all(conf_iterator(lambda conf:
                                                 conf.version == (3, 5)))
    intolerancies["TLS 1.3"] = all(conf_iterator(lambda conf:
                                                 conf.version == (3, 4)))
    intolerancies["TLS 1.2"] = all(conf_iterator(lambda conf:
                                                 conf.version == (3, 3)))
    intolerancies["TLS 1.1"] = all(conf_iterator(lambda conf:
                                                 conf.version == (3, 2)))
    intolerancies["TLS 1.0"] = all(conf_iterator(lambda conf:
                                                 conf.version == (3, 1)))
    intolerancies["extensions"] = all(conf_iterator(lambda conf:
                                                    conf.extensions and not
                                                    conf.ssl2))

    #for name in ["Xmas tree", "Huge Cipher List",
    #             "Huge Cipher List (trunc c/16388)"]:
    #    intolerancies[name] = all(conf_iterator(lambda conf:
    #                                            conf.name == name))

    if not simple_inspector(scan_with_config(host, port,
            configs["Very Compatible (append c/65536)"], hostname)) and \
            simple_inspector(scan_with_config(host, port,
                configs["Very Compatible"], hostname)):
        bad = configs["Very Compatible (append c/65536)"]
        good = configs["Very Compatible"]
        def test_cb(client_hello):
            ret = scan_with_config(host, port, lambda _:client_hello, hostname)
            return simple_inspector(ret)
        bisect = Bisect(good, bad, hostname, test_cb)
        good, bad = bisect.run()
        intolerancies["size c/{0}".format(len(bad.write()))] = True
        intolerancies["size c/{0}".format(len(good.write()))] = False

    if not simple_inspector(scan_with_config(host, port,
            configs["Very Compatible (append e/65536)"], hostname)) and \
            simple_inspector(scan_with_config(host, port,
                configs["Very Compatible"], hostname)):
        bad = configs["Very Compatible (append e/65536)"]
        good = configs["Very Compatible"]
        def test_cb(client_hello):
            ret = scan_with_config(host, port, lambda _:client_hello, hostname)
            return simple_inspector(ret)
        bisect = Bisect(good, bad, hostname, test_cb)
        good, bad = bisect.run()
        intolerancies["size e/{0}".format(len(bad.write()))] = True
        intolerancies["size e/{0}".format(len(good.write()))] = False

    if json_out:
        print(json.dumps(intolerancies))
    else:
        if verbose:
            print()
        print("Host {0}:{1} scan complete".format(host, port))
        if hostname:
            print("SNI hostname used: {0}".format(hostname))
        if verbose:
            print()
            print("Individual probe results:")
            for desc, ret in sorted(results.items()):
                print(verbose_inspector(desc, ret))

        print()
        print("Intolerance to:")
        for intolerance, value in sorted(intolerancies.items()):
            print(" {0:20}: {1}".format(intolerance,
                                    "PRESENT" if value else "absent"))

def single_probe(name):
    print(verbose_inspector(name, scan_with_config(host, port,
        configs[name], hostname)))


def usage():
    print("./cscan.py [ARGUMENTS] host[:port] [SNI-HOST-NAME]")
    print()
    print("-l, --list           List probe names")
    print("-p name, --probe     Run just a single probe")
    print("-j, --json           Output in JSON format")
    print("-v, --verbose        Use verbose output")

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "jvhlp:",
                                   ["json", "verbose", "help", "list",
                                    "probe"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    json_out = False
    verbose = False
    list_probes = False
    run_probe = None

    for opt, arg in opts:
        if opt in ('-j', '--json'):
            json_out = True
        elif opt in ('-v', '--verbose'):
            verbose = True
        elif opt in ('-h', '--help'):
            usage()
            sys.exit(0)
        elif opt in ('-l', '--list'):
            list_probes = True
        elif opt in ('-p', '--probe'):
            run_probe = arg
        else:
            raise AssertionError("Unknown option {0}".format(opt))

    if len(args) > 2:
        print("Too many arguments")
        usage()
        sys.exit(2)

    load_configs()

    if list_probes:
        for desc, ret in sorted(configs.items()):
            print("{0}: {1}".format(desc, ret.__doc__))
        sys.exit(0)

    hostname = None
    if len(args) == 2:
        hostname = args[1]
    hostaddr = args[0].split(":")
    if len(hostaddr) > 1:
        host, port = hostaddr
    else:
        host = hostaddr[0]
        port = 443

    if run_probe:
        single_probe(run_probe)
    else:
        scan_TLS_intolerancies(host, port, hostname)
