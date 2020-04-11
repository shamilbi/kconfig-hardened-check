# pylint: disable=line-too-long

import sys
from argparse import ArgumentParser
from .parser import Parser
from . import (__version__, Env, supported_archs, detect_arch, detect_version,
               check_config_file, print_checklist)


def construct_checklist(checklist, arch):
    parser = Parser(arch, checklist, 'rules.txt')
    parser.parse()


def main():
    config_checklist = []

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
        arch, msg = detect_arch(args.config)
        if not arch:
            sys.exit('[!] ERROR: {}'.format(msg))
        elif not json_mode:
            print('[+] Detected architecture: {}'.format(arch))

        kernel_version, msg = detect_version(args.config)
        Env.kernel_version = kernel_version
        if not kernel_version:
            sys.exit('[!] ERROR: {}'.format(msg))
        elif not json_mode:
            vstr = '.'.join(str(i) for i in kernel_version)
            print(f'[+] Detected kernel version: {vstr}')

        construct_checklist(config_checklist, arch)
        check_config_file(config_checklist, args.config, arch)
        error_count = len(list(filter(lambda opt: opt.result.startswith('FAIL'), config_checklist)))
        ok_count = len(list(filter(lambda opt: opt.result.startswith('OK'), config_checklist)))
        if not debug_mode and not json_mode:
            print('[+] config check is finished: \'OK\' - {} / \'FAIL\' - {}'.format(ok_count, error_count))
        sys.exit(0)

    if args.print:
        arch = args.print
        construct_checklist(config_checklist, arch)
        if not json_mode:
            print('[+] Printing kernel hardening preferences for {}...'.format(arch))
        print_checklist(config_checklist, False)
        sys.exit(0)

    parser.print_help()
    sys.exit(0)

if __name__ == '__main__':
    main()
