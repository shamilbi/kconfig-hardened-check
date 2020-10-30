# pylint: disable=line-too-long

import sys
from kconfig_hardened_check import Env

# pylint: disable=global-at-module-level


class OptCheck:
    def __init__(self, name, expected, decision, reason):
        self.name = name
        self.expected = expected
        self.decision = decision
        self.reason = reason
        self.state = None
        self.result = None

    def check(self):
        if self.expected == self.state:
            self.result = 'OK'
        elif self.state is None:
            if self.expected == 'is not set':
                self.result = 'OK: not found'
            else:
                self.result = 'FAIL: not found'
        else:
            self.result = 'FAIL: "' + self.state + '"'

        if self.result.startswith('OK'):
            return True, self.result
        return False, self.result

    def table_print(self, with_results):
        print('CONFIG_{:<38}|{:^13}|{:^10}|{:^20}'.format(self.name, self.expected, self.decision, self.reason), end='')
        if with_results:
            print('|   {}'.format(self.result), end='')


class VerCheck:
    def __init__(self, ver_expected):
        self.ver_expected = ver_expected
        self.result = None
        self.exp_str = '.'.join(str(i) for i in self.ver_expected)

    def check(self):
        if Env.kernel_version >= self.ver_expected:
            self.result = f'OK: version >= {self.exp_str}'
            return True, self.result
        self.result = f'FAIL: version < {self.exp_str}'
        return False, self.result

    def table_print(self, with_results):
        ver_req = f'kernel version >= {self.exp_str}'
        print('{:<91}'.format(ver_req), end='')
        if with_results:
            print('|   {}'.format(self.result), end='')


class PresenceCheck:
    def __init__(self, name):
        self.name = name
        self.state = None
        self.result = None

    def check(self):
        if self.state is None:
            self.result = f'FAIL: CONFIG_{self.name} not present'
            return False, self.result
        self.result = 'OK: is present'
        return True, self.result

    def table_print(self, with_results):
        print('CONFIG_{:<84}'.format(self.name + ' is present'), end='')
        if with_results:
            print('|   {}'.format(self.result), end='')


class ComplexOptCheck:
    def __init__(self, *opts):
        self.opts = opts
        self.result = None

    @property
    def name(self):
        return self.opts[0].name

    @property
    def expected(self):
        return self.opts[0].expected

    @property
    def state(self):
        return self.opts[0].state

    @property
    def decision(self):
        return self.opts[0].decision

    @property
    def reason(self):
        return self.opts[0].reason

    def table_print(self, with_results):
        if Env.debug_mode:
            print('    {:87}'.format('<<< ' + self.__class__.__name__ + ' >>>'), end='')
            if with_results:
                print('|   {}'.format(self.result), end='')
            for o in self.opts:
                print()
                o.table_print(with_results)
        else:
            o = self.opts[0]
            o.table_print(False)
            if with_results:
                print('|   {}'.format(self.result), end='')


class OR(ComplexOptCheck):
    # self.opts[0] is the option that this OR-check is about.
    # Use case:
    #     OR(<X_is_hardened>, <X_is_disabled>)
    #     OR(<X_is_hardened>, <X_is_hardened_old>)

    def check(self):
        if not self.opts:
            sys.exit('[!] ERROR: invalid OR check')

        for i, opt in enumerate(self.opts):
            ret, _ = opt.check()
            if ret:
                if i == 0 or not hasattr(opt, 'expected'):
                    self.result = opt.result
                else:
                    self.result = 'OK: CONFIG_{} "{}"'.format(opt.name, opt.expected)
                return True, self.result
        self.result = self.opts[0].result
        return False, self.result


class AND(ComplexOptCheck):
    # self.opts[0] is the option that this AND-check is about.
    # Use case: AND(<suboption>, <main_option>)
    # Suboption is not checked if checking of the main_option is failed.

    def check(self):
        for i, opt in reversed(list(enumerate(self.opts))):
            ret, _ = opt.check()
            if i == 0:
                self.result = opt.result
                return ret, self.result
            if not ret:
                if hasattr(opt, 'expected'):
                    self.result = f'FAIL: CONFIG_{opt.name} not "{opt.expected}"'
                else:
                    self.result = opt.result
                return False, self.result

        sys.exit('[!] ERROR: invalid AND check')
