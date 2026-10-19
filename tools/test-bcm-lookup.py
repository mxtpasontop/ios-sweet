#!/usr/bin/env python3
"""Host checks of patch 0089's read-only BCM parser using synthetic cmd-db data."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def additions(path):
    result, active = [], False
    for line in (ROOT / 'xnu/patches/0089-sweet-scm-crypto-resources.patch').read_text().splitlines(True):
        if line.startswith('+++ '):
            active = line.rstrip() == '+++ b/' + path
        elif active and line.startswith('+'):
            result.append(line[1:])
    return ''.join(result)


PRELUDE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "sweet_rpmh.h"
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); abort(); } } while (0)
#define RH_DB_HEADER 144u
#define RH_DB_ENTRY 24u
static unsigned char db[512];
static uint32_t rh_db_size=sizeof(db);
static uintptr_t rh_db;
static unsigned rh_lock, maps;
static int map_error;
static int rh_map(void) { maps++; return map_error; }
static bool rh_range(uint32_t off, uint32_t len) { return off <= rh_db_size && len <= rh_db_size-off; }
static uint32_t rh_read(uintptr_t base, uint32_t off) {
    CHECK(base==rh_db && !(off & 3) && rh_range(off, 4));
    return (uint32_t)db[off] | (uint32_t)db[off+1]<<8 | (uint32_t)db[off+2]<<16 | (uint32_t)db[off+3]<<24;
}
static uint16_t rh_db16(uint32_t off) {
    CHECK(!(off & 1)); return (uint16_t)(rh_read(rh_db, off & ~3u) >> (8u*(off & 3u)));
}
static void put16(unsigned off, unsigned x) { db[off]=x; db[off+1]=x>>8; }
static void put32(unsigned off, uint32_t x) { put16(off,x); put16(off+2,x>>16); }
static void fixture(unsigned shift) {
    memset(db,0,sizeof(db)); rh_lock=maps=0; map_error=0;
    put16(8,5); put16(10,16); put16(12,128); put16(14,1); put16(16,0x100);
    memcpy(db+160,"CE0",3); put32(176,0x50024); put16(180,8); put16(182,shift);
    put32(272+shift,0x87654321u); put16(276+shift,0x1234);
    db[278+shift]=7;db[279+shift]=9;
}
static void fails(const char *name, int err) {
    struct sweet_rpmh_bcm before, out;
    memset(&before,0x55,sizeof(before)); out=before;
    CHECK(sweet_rpmh_bcm_info(name,&out)==err);
    CHECK(!memcmp(&before,&out,sizeof(out)) && rh_lock==0);
}
'''

MAIN = r'''
int main(void) {
    struct sweet_rpmh_bcm b;
    for (unsigned align=0;align<4;align++) {
        fixture(align); CHECK(!sweet_rpmh_bcm_info("CE0",&b));
        CHECK(b.address==0x50024 && b.unit==0x87654321u && b.width==0x1234);
        CHECK(b.vcd==7 && b.reserved==9 && b.version==0x100 && !rh_lock && maps==1);
    }
    fixture(0); fails("missing",ENODEV);
    fixture(0); fails("",EINVAL); CHECK(!maps);
    fixture(0); fails("ABCDEFGHI",EINVAL); CHECK(!maps);
    fixture(0); CHECK(sweet_rpmh_bcm_info(NULL,&b)==EINVAL && !maps);
    fixture(0); CHECK(sweet_rpmh_bcm_info("CE0",NULL)==EINVAL && !maps);
    fixture(0); rh_lock=1; CHECK(sweet_rpmh_bcm_info("CE0",&b)==EBUSY && !maps && rh_lock==1);
    fixture(0); map_error=EIO; fails("CE0",EIO);
    fixture(0); put16(180,7); fails("CE0",EINVAL);
    fixture(0); put16(182,0xffff); fails("CE0",EINVAL);
    fixture(0); put16(14,0xffff); fails("CE0",EINVAL);
    fixture(0); put16(10,17); fails("CE0",EINVAL);
    fixture(0); put16(8,4); fails("CE0",EINVAL);
    fixture(0); put32(176,0x40024); fails("CE0",EINVAL);
    fixture(0); put32(176,0x50025); fails("CE0",EINVAL);
    fixture(0); put16(14,2); memcpy(db+184,db+160,24); fails("CE0",ENODEV);
    fixture(0); memcpy(db+160,"ABCDEFGH",8); CHECK(!sweet_rpmh_bcm_info("ABCDEFGH",&b));
    puts("BCM lookup tests: 20 cases passed");
    return 0;
}
'''


def main():
    text = additions('bsd/dev/sweet_rpmh.c')
    text = text[text.index('/* Linux qcom_icc_bcm_init'):]
    with tempfile.TemporaryDirectory(prefix='sweet-bcm-test-') as tmp:
        d = Path(tmp)
        (d / 'sweet_rpmh.h').write_text(additions('bsd/dev/sweet_rpmh.h'))
        c = d / 'test.c'
        c.write_text(PRELUDE + text + MAIN)
        exe = d / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-I', str(d), str(c), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
