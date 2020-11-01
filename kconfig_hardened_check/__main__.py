# pylint: disable=line-too-long

import sys
from argparse import ArgumentParser
from kconfig_hardened_check.parser import Parser
from kconfig_hardened_check import (
    __version__, Env, supported_archs, detect_arch, detect_version,
    check_config_file, print_checklist)


def construct_checklist():
    parser = Parser('rules.txt')
    parser.parse()
    return parser.checklist


def main():
    parser = ArgumentParser(prog='kconfig-hardened-check',
                            description='Checks the hardening options in the Linux kernel config')
    parser.add_argument('-p', '--print', choices=supported_archs,
                        help='print hardening preferences for selected architecture')
    parser.add_argument('-c', '--config',
                        help='check the config_file against these preferences')
    parser.add_argument('--debug', action='store_true',
                        help='enable verbose debug mode')
    parser.add_argument('--json', action='store_true',
                        help='print results in JSON format')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    args = parser.parse_args()
    main2(args)
    #parser.print_help()
    sys.exit(0)


def main2(args):
    if args.debug:
        Env.debug_mode = True
        print('[!] WARNING: debug mode is enabled')
    if args.json:
        Env.json_mode = True
    debug_mode = Env.debug_mode
    json_mode = Env.json_mode
    if debug_mode and json_mode:
        sys.exit('[!] ERROR: options --debug and --json cannot be used simultaneously')

    if args.config:
        Env.kernel_arch, msg = detect_arch(args.config)
        if not Env.kernel_arch:
            sys.exit('[!] ERROR: {}'.format(msg))
        elif not json_mode:
            print('[+] Detected architecture: {}'.format(Env.kernel_arch))

        kernel_version, msg = detect_version(args.config)
        Env.kernel_version = kernel_version
        if not kernel_version:
            sys.exit('[!] ERROR: {}'.format(msg))
        elif not json_mode:
            vstr = '.'.join(str(i) for i in kernel_version)
            print(f'[+] Detected kernel version: {vstr}')

        config_checklist = construct_checklist()
        check_config_file(config_checklist, args.config)
        error_count = len(list(filter(lambda opt: opt.result.startswith('FAIL'), config_checklist)))
        ok_count = len(list(filter(lambda opt: opt.result.startswith('OK'), config_checklist)))
        if not debug_mode and not json_mode:
            print(f'[+] Config check is finished: \'OK\' - {ok_count} / \'FAIL\' - {error_count}')
        return

    if args.print:
        Env.kernel_arch = args.print
        config_checklist = construct_checklist()
        if not json_mode:
            print('[+] Printing kernel hardening preferences for {}...'.format(Env.kernel_arch))
        print_checklist(config_checklist, False)
        sys.exit(0)


if __name__ == '__main__':
    main()
