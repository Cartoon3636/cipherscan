# Copyright 2016(c) Hubert Kario
# This work is released under the Mozilla Public License Version 2.0
"""tlslite-ng based server configuration (and bug) scanner."""

from __future__ import print_function
from tlslite.messages import ClientHello, ServerHello, ServerHelloDone, Alert
from tlslite.constants import CipherSuite, \
        AlertLevel
from cscan.constants import ExtensionType
from tlslite.extensions import TLSExtension
import sys
import json
import getopt
import itertools
import copy

from cscan.scanner import Scanner
from cscan.config import Xmas_tree, IE_6, IE_8_Win_XP, \
        IE_11_Win_7, IE_11_Win_8_1, Firefox_46, Firefox_42, \
        VeryCompatible
from cscan.modifiers import no_sni, set_hello_version, set_record_version, \
        no_extensions, truncate_ciphers_to_size, append_ciphers_to_size, \
        extend_with_ext_to_size, add_empty_ext, add_one_to_pad_extension, \
        set_extensions_to_size, append_ciphers_to_number, leave_only_ext, \
        ext_id_to_short_name, no_empty_last_ext, extra_sig_algs, \
        extra_groups, add_compressions_to_number, make_secure_renego_ext, \
        make_secure_renego_scsv, extend_with_exts_to_size
from cscan.bisector import Bisect


def scan_with_config(host, port, conf, hostname, __sentry=None, __cache={}):
    """Connect to server and return set of exchanged messages."""
    assert __sentry is None
    key = (host, port, conf, hostname)
    if key in __cache:
        if verbose and not json_out:
            print(":", end='')
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
        self.ssl2 = False
        self.ciphers = [i for i in self.ciphers if i <= 0xffff and
                        i != CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        self.extensions = [TLSExtension(extType=ExtensionType.
                                       renegotiation_info)
                           .create(bytearray(1))]

def simple_inspector(result):
    """
    Perform simple check to see if connection was successful.

    Returns True is connection was successful, server replied with
    ServerHello and ServerHelloDone messages, and the cipher selected
    was present in ciphers advertised by client, False otherwise
    """
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


def simple_renego_inspector(result):
    """
    Perform simple check to see if server supports secure renego indication.

    Returns True if connection supports secure rengotiation on top of checks
    performed by simple_inspector()
    """
    if not simple_inspector(result):
        return False
    # check if renegotiation info is returned by server and valid
    sh = next((x for x in result if isinstance(x, ServerHello)), None)
    if sh and sh.extensions:
        ext = next((i for i in sh.extensions
                    if i.extType == ExtensionType.renegotiation_info), None)
        if ext and ext.extData == bytearray(1):
            return True
    return False


def verbose_inspector(desc, result):
    """Describe the connection result in human-readable form."""
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
    """Load known client configurations for later use in scanning."""
    base_configs = [Xmas_tree, Firefox_42, IE_8_Win_XP, IE_11_Win_7,
                    VeryCompatible, IE_6_ext_tls_1_0]
    for conf in base_configs:
        # only no extensions
        gen = no_extensions(conf())
        configs[gen.name] = gen

        gen = add_empty_ext(no_extensions(conf()), 38)
        configs[gen.name] = gen

        gen = no_empty_last_ext(add_empty_ext(no_extensions(conf()), 38))
        configs[gen.name] = gen

        gen = no_sni(conf())
        configs[gen.name] = gen

        gen = no_empty_last_ext(conf())
        configs[gen.name] = gen

        # single ext alone
        for ext_id in (ExtensionType.server_name,
                       ExtensionType.extended_master_secret,
                       ExtensionType.status_request,
                       ExtensionType.encrypt_then_mac,
                       ExtensionType.signature_algorithms,
                       ExtensionType.supports_npn,
                       ExtensionType.alpn,
                       ExtensionType.pre_shared_key,
                       ExtensionType.key_share):
            gen = leave_only_ext(conf(), ext_id)
            configs[gen.name] = gen

            # or with a short padding extension
            gen = no_empty_last_ext(leave_only_ext(conf(), ext_id))
            configs[gen.name] = gen

        # add custom ext code points
        for ext_id in (ExtensionType.extended_master_secret,
                       ExtensionType.encrypt_then_mac,
                       ExtensionType.client_hello_padding,
                       38,
                       ExtensionType.key_share,
                       ExtensionType.supports_npn):
            gen = add_empty_ext(conf(), ext_id)
            configs[gen.name] = gen

            gen = no_empty_last_ext(add_empty_ext(conf(), ext_id))
            configs[gen.name] = gen

        for version in ((3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 254),
                        (4, 0), (4, 3), (255, 255)):
            if conf().version != version:
                # just changed version
                gen = set_hello_version(conf(), version)
                if gen.record_version > version:
                    gen = set_record_version(gen, version)
                configs[gen.name] = gen

                # changed version and no extensions
                gen = set_hello_version(conf(), version)
                if gen.record_version > version:
                    gen = set_record_version(gen, version)
                gen = no_extensions(gen)
                configs[gen.name] = gen

                # changed version and no sni
                gen = set_hello_version(conf(), version)
                if gen.record_version > version:
                    gen = set_record_version(gen, version)
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

    gen = extend_with_ext_to_size(IE_8_Win_XP(), 200)
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

    # Very Compatible
    gen = VeryCompatible()
    configs[gen.name] = gen

def scan_TLS_intolerancies(host, port, hostname):
    """Look for intolerancies (version, extensions, ...) in a TLS server."""
    results = {}

    def result_iterator(predicate):
        """
        Selecting iterator over cached results.

        Looks for matching result from already performed scans
        """
        return (not simple_inspector(results[name]) for name in results
                if predicate(configs[name]))

    def result_cache(name, conf):
        """Perform scan if config is not in results, caches result."""
        return results[name] if name in results \
            else results.setdefault(name, scan_with_config(host, port, conf,
                                                           hostname))

    def conf_iterator(predicate):
        """
        Caching, selecting iterator over configs.

        Returns an iterator that will go over configs that match the provided
        predicate (a function that returns true or false depending if given
        config is ok for test at hand) while saving the results to the
        cache/verbose `results` log/dictionary

        The iterator returns False for every connection that succeeded
        (meaning the server is NOT intolerant to config and True to mean
        that server IS intolerant to config.
        """
        scan_iter = (not simple_inspector(result_cache(name, conf))
                     for name, conf in configs.items()
                     if predicate(conf))
        return itertools.chain(result_iterator(predicate), scan_iter)

    def ext_checker(ext_type):
        """create generator that will check if extension is present"""
        return lambda exts, t=ext_type: any(i.extType == t for i in exts)

    def check_extension(ext_id):
        """Test for tolerance of single extension"""
        checker = ext_checker(ext_id)
        ext_name = ext_id_to_short_name(ext_id)
        intolerancies["ext:" + ext_name] =\
                all(conf_iterator(lambda conf: conf.extensions and
                                  checker(conf.extensions) and
                                  not conf.ssl2))

    if run_all:
        sum(conf_iterator(lambda conf: True))

    host_up = not all(conf_iterator(lambda conf: True))

    intolerancies = {}
    if not host_up:
        if json_out:
            print(json.dumps(intolerancies))
        else:
            print("Host does not seem to support SSL or TLS protocol")
        return

    intolerancies["SSL 255.255"] = all(conf_iterator(lambda conf:
                                                     conf.version == (255, 255)))
    intolerancies["SSL 4.3"] = all(conf_iterator(lambda conf:
                                                 conf.version == (4, 3)))
    intolerancies["SSL 4.0"] = all(conf_iterator(lambda conf:
                                                 conf.version == (4, 0)))
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
                                                    conf.extensions and
                                                    not conf.ssl2 and
                                                    [i.extType for i in
                                                     conf.extensions] != [0]))
    if hostname:
        check_extension(ExtensionType.server_name)

    for ext_id in (ExtensionType.extended_master_secret,
                   ExtensionType.status_request,
                   ExtensionType.encrypt_then_mac,
                   ExtensionType.client_hello_padding,
                   ExtensionType.alpn,
                   38,
                   ExtensionType.key_share,
                   ExtensionType.supports_npn):
        check_extension(ext_id)

    #for name in ["Xmas tree", "Very Compatible"]:
    #    intolerancies["x:" + name] = all(conf_iterator(lambda conf:
    #                                                   conf.name == name))

    # check for last extension empty intolerance
    def last_ext_empty(conf):
        if not conf.extensions:
            return False

        if not hostname and \
                conf.extensions[-1].extType == ExtensionType.server_name:
            if len(conf.extensions) == 1:
                return False
            return not conf.extensions[-2].extData
        elif hostname and conf.extensions[-1].extType == ExtensionType.server_name:
            return False
        return not conf.extensions[-1].extData

    def last_ext_not_empty(conf):
        if not conf.extensions:
            return False

        if not hostname and \
                conf.extensions[-1].extType == ExtensionType.server_name:
            if len(conf.extensions) == 1:
                return False
            return bool(conf.extensions[-2].extData)
        elif hostname and conf.extensions[-1].extType == ExtensionType.server_name:
            return True
        return bool(conf.extensions[-1].extData)

    if all(conf_iterator(last_ext_empty)) and not \
            all(conf_iterator(last_ext_not_empty)):
        intolerancies["last ext empty"] = True
    if not all(conf_iterator(last_ext_empty)) and not \
                all(conf_iterator(last_ext_not_empty)):
        intolerancies["last ext empty"] = False

    # check if secure renego is supported correctly:
    all(conf_iterator(lambda conf:
                      conf.version >= (3, 1) and
                      (CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV in
                       conf.ciphers
                       or conf.extensions and
                         any(i.extType == ExtensionType.renegotiation_info
                             for i in conf.extensions))))
    good_renego_conf = next((configs[name] for name, result in results.items()
                            if simple_renego_inspector(result) and
                            result[0].client_version >= (3, 1)), None)
    if good_renego_conf:
        secure_ext_gen = make_secure_renego_ext(copy.deepcopy(good_renego_conf))
        secure_scsv_gen = make_secure_renego_scsv(copy.deepcopy(good_renego_conf))
        secure_ext = simple_renego_inspector(scan_with_config(host, port,
            secure_ext_gen, hostname))
        secure_scsv = simple_renego_inspector(scan_with_config(host, port,
            secure_scsv_gen, hostname))
        if secure_ext and secure_scsv:
            intolerancies["secure renego"] = False
        else:
            intolerancies["secure renego ext"] = not secure_ext
            intolerancies["secure renego scsv"] = not secure_scsv

    # basic bisector callback
    def test_cb(client_hello):
        ret = scan_with_config(host, port, lambda _:client_hello, hostname)
        return simple_inspector(ret)

    # check for intolerance to undefined signature algorithms
    good_conf = next((configs[name] for name, result in results.items()
                      if simple_inspector(result) and result[0].extensions and
                      any(i.extType == ExtensionType.signature_algorithms for i
                          in result[0].extensions)), None)
    if good_conf:
        intolerancies["more sigalgs"] = not simple_inspector(scan_with_config(
            host, port, extra_sig_algs(copy.deepcopy(good_conf)), hostname))

    # check for intolerance to undefined and uncommon groups
    good_conf = next((configs[name] for name, result in results.items()
                      if simple_inspector(result) and result[0].extensions and
                      any(i.extType == ExtensionType.supported_groups for i
                          in result[0].extensions)), None)
    if good_conf:
        intolerancies["more groups"] = not simple_inspector(scan_with_config(
            host, port, extra_groups(copy.deepcopy(good_conf)), hostname))

    # most size intolerancies lie between 16385 and 16389 so short-circuit to
    # them if possible
    good_conf = next((configs[name] for name, result in results.items()
                      if simple_inspector(result)), None)

    cipher_num_intolerance = None
    if good_conf:
        size_c_16382 = simple_inspector(scan_with_config(host, port,
            append_ciphers_to_size(copy.deepcopy(good_conf), 16382), hostname))
        size_c_16392 = simple_inspector(scan_with_config(host, port,
            append_ciphers_to_size(copy.deepcopy(good_conf), 16392), hostname))

        if size_c_16382 and not size_c_16392:
            good = append_ciphers_to_size(copy.deepcopy(good_conf), 16382)
            bad = append_ciphers_to_size(copy.deepcopy(good_conf), 16392)
        elif not size_c_16382:
            good = good_conf
            bad = append_ciphers_to_size(copy.deepcopy(good_conf), 16382)
        else:
            bad = append_ciphers_to_size(copy.deepcopy(good_conf), 65536)
            bad_scan = scan_with_config(host, port, bad, hostname)
            size_c_65536 = simple_inspector(bad_scan)
            if size_c_65536:
                good = None
                intolerancies["size c/65536"] = False
                intolerancies["size c#/{0}".format(len(bad_scan[0].cipher_suites))] = False
            else:
                good = append_ciphers_to_size(copy.deepcopy(good_conf), 16392)

        if good:
            bisect = Bisect(good, bad, hostname, test_cb)
            good_h, bad_h = bisect.run()
            # check what happens if the boundary lands on an odd byte
            good = add_one_to_pad_extension(copy.deepcopy(good_conf))
            bad = add_one_to_pad_extension(copy.deepcopy(good_conf))
            # short circuit to around the boundary previously found
            good = append_ciphers_to_size(good, len(good_h.write()) - 1)
            bad = append_ciphers_to_size(bad, len(bad_h.write()) + 1)
            bisect = Bisect(good, bad, hostname, test_cb)
            good_h2, bad_h2 = bisect.run()
            # report with full precision (highest accepted, smallest rejected
            intolerancies["size c/{0}".format(min(len(bad_h.write()),
                                                  len(bad_h2.write())))] = True
            intolerancies["size c/{0}".format(max(len(good_h.write()),
                                                  len(good_h2.write())))] = False
            intolerancies["size c#/{0}".format(len(bad_h.cipher_suites))] = True
            cipher_num_intolerance = len(bad_h.cipher_suites)
            intolerancies["size c#/{0}".format(len(good_h.cipher_suites))] = False

    # test extension size intolerance, again, most lie between 16385
    # and 16389 so short-circuit if possible
    if not ('size c#/129' in intolerancies or
            cipher_num_intolerance and cipher_num_intolerance < 600 and \
            intolerancies["TLS 1.3"] and not intolerancies["TLS 1.2"] and \
            not intolerancies["extensions"]):
        good_conf = next((configs[name] for name, result in results.items()
                          if configs[name].extensions and
                          simple_inspector(result)), None)

        size_limit = False

        if good_conf:
            size_e_16382 = simple_inspector(scan_with_config(host, port,
                extend_with_ext_to_size(copy.deepcopy(good_conf), 16382), hostname))
            size_e_16392 = simple_inspector(scan_with_config(host, port,
                extend_with_ext_to_size(copy.deepcopy(good_conf), 16392), hostname))

            if size_e_16382 and not size_e_16392:
                good = extend_with_ext_to_size(copy.deepcopy(good_conf), 16382)
                bad = extend_with_ext_to_size(copy.deepcopy(good_conf), 16392)
            elif not size_e_16382:
                good = good_conf
                bad = extend_with_ext_to_size(copy.deepcopy(good_conf), 16382)
            else:
                bad = extend_with_ext_to_size(copy.deepcopy(good_conf), 65536)
                size_e_65536 = simple_inspector(scan_with_config(host, port,
                    bad, hostname))
                if size_e_65536:
                    good = None
                    intolerancies["size e/65536"] = False
                else:
                    good = extend_with_ext_to_size(copy.deepcopy(good_conf), 16392)

            if good:
                size_limit = True
                bisect = Bisect(good, bad, hostname, test_cb)
                good_h, bad_h = bisect.run()
                intolerancies["size e/{0}".format(len(bad_h.write()))] = True
                intolerancies["size e/{0}".format(len(good_h.write()))] = False

            # check if server doesn't have 256 <= x < 512 bytes intolerance
            all_configs_iter = conf_iterator(lambda conf: conf.extensions
                                             and not conf.ssl2)
            while True:
                small_conf = next((configs[name] for name, result in results.items()
                                   if simple_inspector(result) and
                                   result[0].extensions and
                                   len(result[0].write()) < 256), None)
                if small_conf is None:
                    if all(all_configs_iter):
                        continue
                    else:
                        break

                medium_conf = extend_with_ext_to_size(copy.deepcopy(small_conf),
                                                      384)
                big_conf = extend_with_ext_to_size(copy.deepcopy(small_conf),
                                                   640)
                size_e_384 = simple_inspector(scan_with_config(host, port,
                                              medium_conf, hostname))
                size_e_640 = simple_inspector(scan_with_config(host, port,
                                              big_conf, hostname))
                if not size_e_640:
                    intolerancies["size e/640"] = True
                    # different bug, should have been caught by the generic
                    # code
                    break

                if size_e_384:
                    intolerancies["size e/384"] = False
                    break

                bisect = Bisect(small_conf, medium_conf, hostname, test_cb)
                good_h, bad_h = bisect.run()
                intolerancies["size e/{0}".format(len(good_h.write()))] = False
                intolerancies["size e/{0}".format(len(bad_h.write()))] = True

                bisect = Bisect(big_conf, medium_conf, hostname, test_cb)
                good_h, bad_h = bisect.run()
                intolerancies["size e/{0}".format(len(good_h.write()))] = False
                intolerancies["size e/{0}".format(len(bad_h.write()))] = True

                break

            # double check the result of the scan with padding extension
            size_e_16382 = simple_inspector(scan_with_config(host, port,
                extend_with_ext_to_size(copy.deepcopy(good_conf), 16382,
                                        84), hostname))
            size_e_16392 = simple_inspector(scan_with_config(host, port,
                extend_with_ext_to_size(copy.deepcopy(good_conf), 16392,
                                        84), hostname))

            if size_e_16382 and not size_e_16392:
                good = extend_with_ext_to_size(copy.deepcopy(good_conf), 16382,
                                               84)
                bad = extend_with_ext_to_size(copy.deepcopy(good_conf), 16392,
                                              84)
            elif not size_e_16382:
                good = good_conf
                bad = extend_with_ext_to_size(copy.deepcopy(good_conf), 16382,
                                              84)
            else:
                bad = extend_with_ext_to_size(copy.deepcopy(good_conf), 65536,
                                              84)
                size_e_65536 = simple_inspector(scan_with_config(host, port,
                    bad, hostname))
                if size_e_65536:
                    good = None
                    intolerancies["size #84 e/65536"] = False
                else:
                    good = extend_with_ext_to_size(copy.deepcopy(good_conf), 16392,
                                                   84)

            if good:
                size_limit = True
                bisect = Bisect(good, bad, hostname, test_cb)
                good_h, bad_h = bisect.run()
                intolerancies["size #84 e/{0}".format(len(bad_h.write()))] = True
                intolerancies["size #84 e/{0}".format(len(good_h.write()))] = False

            # if no intolerance detected, look for higher sizes
            if not size_limit:
                size_max_gen = set_extensions_to_size(copy.deepcopy(good_conf),
                                                      0xffff)
                size_max_gen = append_ciphers_to_number(size_max_gen,
                                                        0xfffe//2)
                size_max_gen = add_compressions_to_number(size_max_gen, 0xff)
                size_max = scan_with_config(host, port, size_max_gen, hostname)
                if simple_inspector(size_max):
                    intolerancies["size {0}".format(len(size_max[0].write()))]\
                            = False
                else:
                    bad = size_max_gen
                    good = copy.deepcopy(good_conf)
                    bisect = Bisect(good, bad, hostname, test_cb)
                    good_h, bad_h = bisect.run()
                    good_len = len(good_h.write())
                    bad_len = len(bad_h.write())
                    if bad_len - 1 != good_len:
                        good = append_ciphers_to_size(copy.deepcopy(good_conf),
                                                      good_len)
                        good = extend_with_ext_to_size(good, good_len)
                        bad = append_ciphers_to_size(copy.deepcopy(good_conf),
                                                     good_len)
                        bad = extend_with_ext_to_size(bad, bad_len)
                        bisect = Bisect(good, bad, hostname, test_cb)
                        good_h, bad_h = bisect.run()
                        good_len = len(good_h.write())
                        bad_len = len(bad_h.write())
                    intolerancies["size {0}".format(bad_len)] = True
                    intolerancies["size {0}".format(good_len)] = False

            # check for intolerance to number of extensions
            def test_renego_cb(client_hello):
                assert any(i.extType == ExtensionType.renegotiation_info
                           for i in client_hello.extensions)
                ret = scan_with_config(host, port, lambda _:client_hello,
                                       hostname)
                return simple_renego_inspector(ret)

            if not ('secure renego ext' in intolerancies and
                    intolerancies["secure renego ext"]):
                size_max_gen = extend_with_exts_to_size(copy.deepcopy(secure_ext_gen),
                                                       65536)
                size_max_scan = scan_with_config(host, port,
                                                 size_max_gen, hostname)
                size_max = simple_renego_inspector(size_max_scan)
                if size_max:
                    intolerancies["size e#/{0}".format(len(size_max_scan[0].extensions))] = False
                else:
                    bisect = Bisect(secure_ext_gen, size_max_gen, hostname,
                                    test_renego_cb)
                    good_h, bad_h = bisect.run()
                    intolerancies["size e#/{0}".format(len(good_h.extensions))] = False
                    intolerancies["size e#/{0}".format(len(bad_h.extensions))] = True

    if json_out:
        print(json.dumps(intolerancies))
    else:
        if not no_header:
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
    """Run a single probe against a server, print result."""
    print(verbose_inspector(name, scan_with_config(host, port,
          configs[name], hostname)))


def usage():
    """Print usage information."""
    print("./cscan.py [ARGUMENTS] host[:port] [SNI-HOST-NAME]")
    print()
    print("-a                   Run all probes")
    print("-l, --list           List probe names")
    print("-p name, --probe     Run just a single probe")
    print("-j, --json           Output in JSON format")
    print("-v, --verbose        Use verbose output")

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "jvhlp:a",
                                   ["json", "verbose", "help", "list",
                                    "probe=", "no-header"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    json_out = False
    verbose = False
    list_probes = False
    run_probe = None
    no_header = False
    run_all = False

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
        elif opt in ('--no-header', ):
            no_header = True
        elif opt == '-a':
            run_all = True
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
