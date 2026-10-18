#!/usr/bin/env python3
"""Exercise patch 0088's SCM query transport with a simulated monitor.

No phone needed. The inline SMC is replaced; the actual query/probe code is
compiled from the patch. Checks continuation tokens, busy retries, signed
status handling, convention fallback, and the absence of state-changing calls.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0088-sweet-scm-query.patch'


def source():
    lines = PATCH.read_text().splitlines(True)
    start = lines.index('+++ b/bsd/dev/sweet_scm.c\n') + 1
    return ''.join(line[1:] for line in lines[start:] if line.startswith('+'))


HARNESS = r'''
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); abort(); } } while (0)
extern void abort(void);
static unsigned kind, calls, sleeps, syncs;
static int enabled = 1;
static uint32_t expected_fn, expected_arg;
static void reset(unsigned k) { kind=k; calls=sleeps=syncs=0; }
void delay(int us) { CHECK(us == 30000); sleeps++; }
void sweet_log_sync(void) { syncs++; }
int PE_parse_boot_argn(const char *name, void *value, int size) {
    (void)name; CHECK(size == sizeof(int)); *(int *)value=enabled; return 1;
}
static void scm_smccc(struct scm_regs *r) {
    unsigned n = calls++;
    if (kind <= 4) {
        CHECK(r->a[1] == 1 && r->a[2] == expected_arg);
        CHECK(r->a[3] == 0 && r->a[4] == 0 && r->a[5] == 0);
        if (kind == 1 && n) {
            CHECK(r->a[0] == 1 && r->a[6] == 0x123456789abcdef0ULL);
        } else if (kind == 4 && n) {
            CHECK(r->a[0] == 1 && r->a[6] == 99);
        } else {
            CHECK(r->a[0] == expected_fn && r->a[6] == 0);
        }
        if ((kind == 1 && !n) || kind == 4) {
            r->a[0] = 1; r->a[6] = kind == 4 ? 99 : 0x123456789abcdef0ULL;
        } else if (kind == 2 || (kind == 3 && !n)) {
            r->a[0] = 0xfffffff4u; r->a[6] = 0xdead;
        } else {
            r->a[0] = 0; r->a[1] = 1;
        }
        return;
    }
    /* Probe integration: only INFO queries and the PIL support query. */
    uint32_t fn = (uint32_t)r->a[0];
    uint32_t base = fn & ~(SCM_FAST | SCM_64);
    CHECK(base == SCM_INFO_AVAIL || base == SCM_PAS_SUPPORTED);
    CHECK(r->a[1] == 1 && r->a[3] == 0 && r->a[4] == 0 && r->a[5] == 0 && r->a[6] == 0);
    if (!n) {
        CHECK(fn == (SCM_FAST | SCM_64 | SCM_INFO_AVAIL));
        CHECK(r->a[2] == (SCM_FAST | SCM_INFO_AVAIL));
        if (kind == 6) { r->a[0] = 0xffffffffu; return; }
        if (kind == 8) { r->a[0] = 0xfffffffcu; return; }
    } else if (kind == 6 && n == 1) {
        CHECK(fn == (SCM_FAST | SCM_INFO_AVAIL));
    } else {
        CHECK(!(fn & SCM_FAST));
        CHECK((fn & SCM_64) == (kind == 6 ? 0 : SCM_64));
        if (base == SCM_PAS_SUPPORTED) { CHECK(r->a[2] == 13); }
        else { CHECK((r->a[2] & ~0xffULL) == (SCM_SIP | 0x200)); }
    }
    r->a[0] = 0; r->a[1] = kind == 7 && n == 5 ? 0 : 1;
}
int main(void) {
    struct scm_regs r;
    expected_fn=SCM_64 | SCM_INFO_AVAIL; expected_arg=SCM_PAS_SUPPORTED;
    reset(0); CHECK(scm_query(expected_fn, expected_arg, false, &r)); CHECK(calls==1);
    reset(1); CHECK(scm_query(expected_fn, expected_arg, false, &r)); CHECK(calls==2);
    reset(2); CHECK(!scm_query(expected_fn, expected_arg, false, &r)); CHECK(calls==4 && sleeps==3);
    reset(2); CHECK(!scm_query(expected_fn, expected_arg, true, &r)); CHECK(calls==1 && sleeps==0);
    reset(3); CHECK(scm_query(expected_fn, expected_arg, false, &r)); CHECK(calls==2 && sleeps==1);
    reset(4); CHECK(!scm_query(expected_fn, expected_arg, false, &r)); CHECK(calls==65);
    reset(5); sweet_scm_probe(); CHECK(calls==7 && syncs==15);
    reset(6); sweet_scm_probe(); CHECK(calls==8);
    reset(7); sweet_scm_probe(); CHECK(calls==6); /* support query unavailable */
    reset(8); sweet_scm_probe(); CHECK(calls==1); /* unknown ABI error: stop */
    reset(5); enabled=0; sweet_scm_probe(); CHECK(calls==0 && syncs==0);
    puts("SCM query tests: 11 cases passed");
    return 0;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='sweet-scm-test-') as tmp:
        d = Path(tmp)
        headers = {
            'sys/param.h': 'typedef unsigned int uint32_t; typedef int int32_t;\n'
                           'typedef unsigned long long uint64_t;\n'
                           '#define bool _Bool\n#define true 1\n#define false 0\n',
            'sys/systm.h': 'int printf(const char *, ...) __attribute__((format(printf,1,2)));\n'
                           'int puts(const char *);\n',
            'kern/clock.h': 'void delay(int);\n',
            'pexpert/pexpert.h': 'int PE_parse_boot_argn(const char *, void *, int);\n',
        }
        for name, data in headers.items():
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(data)
        c = d / 'test.c'
        c.write_text(source() + HARNESS)
        exe = d / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SWEET', '-DSWEET_SCM_TEST', '-I', str(d),
                        str(c), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
