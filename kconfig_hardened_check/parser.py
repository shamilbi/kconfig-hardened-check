import re
from importlib.resources import open_text
from kconfig_hardened_check.check import OptCheck, VerCheck, OR, AND, PresenceCheck

# pylint: disable=too-many-instance-attributes


class Reason:
    def __init__(self, decision, reason):
        self.decision = decision
        self.reason = reason

    def create_check(self, name, expected):
        return OptCheck(name, expected, self.decision, self.reason)

    def _scan_checks(self, *checks):
        'checks = (name, expected), OptCheck(), ...'
        for c in checks:
            if isinstance(c, (OptCheck, VerCheck, OR, AND, PresenceCheck)):
                yield c
            else:
                name, expected = c
                yield self.create_check(name, expected)

    def create_or(self, *checks):
        'checks = (name, expected), OptCheck(), ...'
        l = list(self._scan_checks(*checks))
        check = OR(*l)
        return check

    def create_and(self, *checks):
        'checks = (name, expected), OptCheck(), ...'
        l = list(self._scan_checks(*checks))
        check = AND(*l)
        return check


class ParseException(Exception):
    pass


def split_by_comma(s):
    return [i.strip() for i in s.split(',')]


class Condition:
    def __init__(self, reason: Reason, level: int, op: str):
        self.reason = reason
        self.level = level
        d = {'or': self.reason.create_or,
             'and': self.reason.create_and}
        self.createF = d[op]
        self.checks = []

    def add_check(self, check, level: int):
        for c in reversed(self.checks):
            if isinstance(c, Condition):
                if level > c.level:
                    c.add_check(check, level)
                    break
                if level == c.level and not c.checks:
                    c.add_check(check, level)
                    break
        else:
            self.checks.append(check)

    def create(self):
        checks = []
        for c in self.checks:
            if isinstance(c, Condition):
                checks.append(c.create())
            else:
                checks.append(c)
        return self.createF(*checks)


class Parser:
    LEVEL_RE = re.compile(r'( *)')
    WORD = '[a-z_]+'
    REASON_RE = re.compile(f'reason: ({WORD}), ({WORD})')
    # reason: kspp, cut_attack_surface
    VAR_RE = re.compile(f'({WORD}): (.*)')
    # devmem_not_set: DEVMEM=, refers to LOCKDOWN
    # or: STRICT_KERNEL_RWX=y
    # arch: X86_64, X86_32
    CHECK_RE_1 = re.compile(r'[^ ,=]+')
    # var
    # STRICT_KERNEL_RWX=y
    CHECK_RE_2 = re.compile(r'=([^ ,]*)')
    # =y

    def __init__(self, arch, rpath):
        'rpath = module.file'
        self.arch = arch
        self.checklist = []
        self.rpath = rpath
        self.skip_level = 0
        self.reason: Reason = None
        self.cond: Condition = None
        self.count = 0
        self.line = ''
        self.level = 0
        self.var_d = {}

    def error(self, msg):
        raise ParseException(f'{msg}: {self.count}: {self.line}')

    def parse(self):
        self.level = 0
        mod_name = '.'.join(__name__.split('.')[:-1])
        # module.parser --> module
        with open_text(mod_name, self.rpath) as fp:
            for self.count, self.line in enumerate(fp, 1):
                self.line = self.line.rstrip()
                if not self.line:
                    continue
                m = self.LEVEL_RE.match(self.line)
                self.level = len(m.group(1))
                self.line = self.line[self.level:]
                # '  xxx' --> 'xxx'
                if self.line.startswith('#'):
                    # comment
                    continue
                if self.skip_level and self.level > self.skip_level:
                    # arch: ...
                    #   ...
                    #   ...
                    continue
                self.skip_level = 0
                self.parse2()
            # last condition (or, and)
            self.create_cond()

    def parse2(self):
        if not self.level:
            # reason only on level 0
            m = self.REASON_RE.match(self.line)
            if not m:
                self.error('bad reason')
            self.reason = Reason(m.group(1), m.group(2))
        else:
            if not self.reason:
                self.error('reason not found')
            if self.cond and self.level <= self.cond.level:
                self.create_cond()
            m = self.VAR_RE.match(self.line)
            if m:
                # var: ...
                self.parse_var(m)
            else:
                # A=y
                # var
                self.parse_check(self.line)

    def parse_var(self, m):
        var = m.group(1)
        rest = m.group(2).lstrip()
        if var == 'reason':
            self.error('bad indent (reason)')
        if var == 'arch':
            if not self.check_arch(rest):
                self.skip_level = self.level
        elif var in ('or', 'and'):
            cond = Condition(self.reason, self.level, var)
            if self.cond:
                self.cond.add_check(cond, self.level)
            else:
                self.cond = cond
            self.parse_check(rest)
        else:
            self.parse_check(rest, var)

    def check_arch(self, rest):
        return self.arch in split_by_comma(rest)
        # X86_64, X86_32

    def create_cond(self):
        if self.cond:
            if not self.cond.checks:
                self.error('bad condition (or, and)')
            check = self.cond.create()
            self.checklist.append(check)
        self.cond = None

    def parse_check(self, line, var=None):
        m = self.CHECK_RE_1.match(line)
        if not m:
            self.error('bad check')
        left = m.group(0)
        line = line[len(left):]
        m = self.CHECK_RE_2.match(line)
        if m:
            val = m.group(1)
            # INTEGRITY=y
            # ARCH_MMAP_RND_BITS=32
            if left == 'version':
                # version=5.5
                check = self.parse_version(val)
            elif left == 'presence':
                # presence=LDISC_AUTOLOAD
                check = PresenceCheck(val)
            else:
                if not val:
                    # LIVEPATCH=
                    val = 'is not set'
                check = self.reason.create_check(left, val)
        else:
            # modules_not_set
            if left not in self.var_d:
                self.error(f'var not found: {left}')
            check = self.var_d[left]
        if var:
            if var in self.var_d:
                self.error(f'var defined twice: {var}')
            self.var_d[var] = check
        elif self.cond:
            self.cond.add_check(check, self.level)
        else:
            self.checklist.append(check)

    def parse_version(self, s):
        digits = s.split('.')
        if not all(i.isdigit() for i in digits):
            self.error('bad version')
        return VerCheck(tuple(int(i) for i in digits))
