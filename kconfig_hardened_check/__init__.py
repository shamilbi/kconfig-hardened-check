#!/usr/bin/python3

#
# This tool helps me to check the Linux kernel Kconfig option list
# against my hardening preferences for X86_64, ARM64, X86_32, and ARM.
# Let the computers do their job!
#
# Author: Alexander Popov <alex.popov@linux.com>
#
# Please don't cry if my Python code looks like C.
#
#
# N.B Hardening command line parameters:
#    slub_debug=FZP
#    slab_nomerge
#    page_alloc.shuffle=1
#    iommu=force (does it help against DMA attacks?)
#    page_poison=1 (if enabled)
#    init_on_alloc=1
#    init_on_free=1
#    loadpin.enforce=1
#
#    Mitigations of CPU vulnerabilities:
#       Аrch-independent:
#           mitigations=auto,nosmt
#       X86:
#           spectre_v2=on
#           pti=on
#           spec_store_bypass_disable=on
#           l1tf=full,force
#           mds=full,nosmt
#           tsx=off
#       ARM64:
#           kpti=on
#           ssbd=force-on
#
# N.B. Hardening sysctls:
#    kernel.kptr_restrict=2
#    kernel.dmesg_restrict=1
#    kernel.perf_event_paranoid=3
#    kernel.kexec_load_disabled=1
#    kernel.yama.ptrace_scope=3
#    user.max_user_namespaces=0
#    kernel.unprivileged_bpf_disabled=1
#    net.core.bpf_jit_harden=2
#
#    vm.unprivileged_userfaultfd=0
#
#    dev.tty.ldisc_autoload=0
#    fs.protected_symlinks=1
#    fs.protected_hardlinks=1
#    fs.protected_fifos=2
#    fs.protected_regular=2
#    fs.suid_dumpable=0
#    kernel.modules_disabled=1

import sys
from collections import OrderedDict
import re
import json
from kconfig_hardened_check.__about__ import __version__
from kconfig_hardened_check.env import Env
from kconfig_hardened_check.check import check_x

# pylint: disable=line-too-long,too-many-branches
# pylint: disable=too-many-statements,global-statement

supported_archs = ['X86_64', 'X86_32', 'ARM64', 'ARM']


def detect_arch(fname):
    with open(fname, 'r') as f:
        arch_pattern = re.compile("CONFIG_[a-zA-Z0-9_]*=y")
        arch = None
        if not Env.json_mode:
            print(f'[+] Config file to check: {fname}')
        for line in f.readlines():
            if arch_pattern.match(line):
                option, _ = line[7:].split('=', 1)
                if option in supported_archs:
                    if not arch:
                        arch = option
                    else:
                        return None, 'more than one supported architecture is detected'
        if not arch:
            return None, 'failed to detect architecture'
        return arch, 'OK'


def detect_version(fname):
    with open(fname, 'r') as f:
        ver_pattern = re.compile("# Linux/.* Kernel Configuration")
        for line in f:
            if ver_pattern.match(line):
                line = line.strip()
                parts = line.split()
                ver_str = parts[2]
                ver_numbers = ver_str.split('.')[:3]
                # 5.5.15-xxx --> 5.5.15
                ver_numbers[-1] = re.sub(r'([0-9]+).*', r'\1', ver_numbers[-1])
                if len(ver_numbers) < 3 or not all(i.isdigit() for i in ver_numbers):
                    msg = f'failed to parse the version "{ver_str}"'
                    return None, msg
                return tuple(int(i) for i in ver_numbers), None
        return None, 'no kernel version detected'


def print_checklist(checklist, with_results):
    if Env.json_mode:
        opts = []
        for o in checklist:
            opt = ['CONFIG_'+o.name, o.expected, o.decision, o.reason]
            if with_results:
                opt.append(o.result)
            opts.append(opt)
        print(json.dumps(opts))
        return

    # table header
    sep_line_len = 91
    if with_results:
        sep_line_len += 30
    print('=' * sep_line_len)
    print('{:^45}|{:^13}|{:^10}|{:^20}'.format('option name', 'desired val', 'decision', 'reason'), end='')
    if with_results:
        print('|   {}'.format('check result'), end='')
    print()
    print('=' * sep_line_len)

    # table contents
    for opt in checklist:
        opt.table_print(with_results)
        print()
        if Env.debug_mode:
            print('-' * sep_line_len)
    print()


def perform_checks(checklist, parsed_options):
    for opt in checklist:
        #if hasattr(opt, 'opts'):
        #    # prepare ComplexOptCheck
        #    for o in opt.opts:
        #        if hasattr(o, 'state'):
        #            o.state = parsed_options.get(o.name, None)
        #else:
        #    # prepare simple check
        #    if not hasattr(opt, 'state'):
        #        sys.exit('[!] ERROR: bad simple check {}'.format(vars(opt)))
        #    opt.state = parsed_options.get(opt.name, None)
        #opt.check()
        check_x(opt, parsed_options)


def check_config_file(checklist, fname):
    with open(fname, 'r') as f:
        parsed_options = OrderedDict()
        opt_is_on = re.compile("CONFIG_[a-zA-Z0-9_]*=[a-zA-Z0-9_\"]*")
        opt_is_off = re.compile("# CONFIG_[a-zA-Z0-9_]* is not set")

        for line in f.readlines():
            line = line.strip()
            option = None
            value = None

            if opt_is_on.match(line):
                option, value = line[7:].split('=', 1)
            elif opt_is_off.match(line):
                option, value = line[9:].split(' ', 1)
                if value != 'is not set':
                    sys.exit('[!] ERROR: bad disabled config option "{}"'.format(line))

            if option in parsed_options:
                sys.exit('[!] ERROR: config option "{}" exists multiple times'.format(line))

            if option is not None:
                parsed_options[option] = value

        perform_checks(checklist, parsed_options)

        if Env.debug_mode:
            known_options = []
            for opt in checklist:
                if hasattr(opt, 'opts'):
                    for o in opt.opts:
                        if hasattr(o, 'name'):
                            known_options.append(o.name)
                else:
                    known_options.append(opt.name)
            for option, value in parsed_options.items():
                if option not in known_options:
                    print('DEBUG: dunno about option {} ({})'.format(option, value))

        print_checklist(checklist, True)
