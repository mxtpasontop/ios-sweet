#!/usr/bin/env python3
"""Check real patched RPMh code against synthetic cmd-db and a TCS model."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def reconstruct(directory):
    wanted = {'bsd/dev/sweet_rpmh.c', 'bsd/dev/sweet_rpmh.h'}
    (directory / 'bsd/dev').mkdir(parents=True)
    for patch in sorted((ROOT / 'xnu/patches').glob('*.patch')):
        sections = re.split(r'(?=^--- )', patch.read_text(errors='replace'), flags=re.M)
        selected = []
        for section in sections:
            m = re.search(r'^\+\+\+ b/(\S+)', section, re.M)
            if m and m[1] in wanted:
                selected.append(section)
        if selected:
            subprocess.run(['patch', '--batch', '--fuzz=0', '-s', '-p1'],
                           cwd=directory, input=''.join(selected), text=True, check=True)
    return (directory / 'bsd/dev/sweet_rpmh.c').read_text()


PRELUDE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "sweet_rpmh.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); abort(); } } while (0)
#define MIN(a,b) ((a)<(b)?(a):(b))
static uintptr_t rh_tcs=0x1000;
static unsigned rh_ncpt=16,rh_lock;
static bool rh_poisoned;
static uint32_t regs[0x3000/4], captured_addr[16],captured_data[16],captured_wait;
static unsigned writes,triggers,ticks,mode;
static int fail_offset=-1, lookup_error, map_error;
static uint32_t rh_read(uintptr_t base,uint32_t off) {
    CHECK(base==rh_tcs && !(off&3) && off<sizeof(regs));return regs[off/4];
}
static void rh_write(uintptr_t base,uint32_t off,uint32_t value);
static bool rh_sync(uint32_t off,uint32_t value) {
    rh_write(rh_tcs,off,value);return (int)off!=fail_offset && rh_read(rh_tcs,off)==value;
}
static void delay(unsigned n);
static int rh_map(void) { return map_error; }
static int rh_lookup(const char *name,uint32_t *address) {
    CHECK(!strcmp(name,"ldoc11"));*address=0x40040;return 0;
}
static struct sweet_rpmh_bcm fixture_info[6];
static unsigned lookup_count;
int sweet_rpmh_bcm_info(const char *name,struct sweet_rpmh_bcm *out) {
    const char *names[]={"CE0","SN11","SN0","SH0","MC0","ACV"};
    lookup_count++;
    if(lookup_error)return lookup_error;
    for(unsigned i=0;i<6;i++)if(!strcmp(name,names[i])){*out=fixture_info[i];return 0;}
    return ENODEV;
}
'''

MODEL = r'''
static void rh_write(uintptr_t base,uint32_t off,uint32_t value) {
    CHECK(base==rh_tcs && !(off&3) && off<2*RH_TCS_STRIDE);
    writes++;
    if(off==RH_IRQ_CLEAR){regs[RH_IRQ_STATUS/4]&=~value;return;}
    regs[off/4]=value;
    if((off%RH_TCS_STRIDE)==RH_CONTROL && (value&RH_TRIGGER)) {
        CHECK(off==RH_CONTROL);triggers++;
        captured_wait=regs[RH_WAIT/4];
        for(unsigned c=0;c<16;c++) {
            captured_addr[c]=regs[(RH_ADDR+c*RH_CMD_STRIDE)/4];
            captured_data[c]=regs[(RH_DATA+c*RH_CMD_STRIDE)/4];
        }
        if(mode!=2)regs[RH_STATUS/4]=0;
    }
}
static void delay(unsigned n) {
    CHECK(n==1);ticks++;
    if(!triggers || mode==1 || mode==2)return;
    regs[RH_STATUS/4]=1;regs[RH_IRQ_STATUS/4]|=1;
    for(unsigned c=0;c<16;c++)if(regs[RH_ENABLE/4]&(1u<<c))
        regs[(RH_CMD_STATUS+c*RH_CMD_STRIDE)/4]=(mode==3 && c==2)?RH_ISSUED:RH_ISSUED|RH_COMPLETE;
}
static void fixture(void) {
    memset(regs,0,sizeof(regs));memset(captured_addr,0,sizeof(captured_addr));
    writes=triggers=ticks=mode=lookup_count=rh_lock=0;fail_offset=-1;
    rh_poisoned=rh_crypto_held=false;lookup_error=map_error=0;rh_ncpt=16;
    regs[RH_IRQ_EN/4]=3;regs[RH_STATUS/4]=regs[(RH_TCS_STRIDE+RH_STATUS)/4]=1;
    const struct sweet_rpmh_bcm values[]={
        {0x500a0,6802,8,6,0,0x1000}, {0x5006c,530000,16,3,0,0x1000},
        {0x50078,530000,16,3,0,0x1000}, {0x5003c,2090000,32,1,0,0x1000},
        {0x50000,1770000,16,0,0,0x1000}, {0x5000c,1,0,11,0,0x1000}
    };memcpy(fixture_info,values,sizeof(values));
}
static void plan_fails(void) {
    struct rh_command cmds[6];uint32_t wait;
    CHECK(rh_crypto_plan(fixture_info,cmds,&wait)==EINVAL && !writes);
}
int main(void) {
    struct rh_command cmds[6];uint32_t wait;
    fixture();CHECK(!rh_crypto_plan(fixture_info,cmds,&wait) && wait==0x3b);
    const uint32_t addresses[]={0x50000,0x5003c,0x5006c,0x50078,0x500a0,0x5000c};
    const uint32_t data[]={0x606f22be,0x602f0eb6,0x20b99d02,0x60b99d02,0x6fffffff,0x60000008};
    for(unsigned i=0;i<6;i++)CHECK(cmds[i].address==addresses[i] && cmds[i].data==data[i]);
    fixture_info[0].unit=0;plan_fails();
    fixture();fixture_info[0].width=0;plan_fails();
    fixture();fixture_info[0].width=65;plan_fails();
    fixture();fixture_info[0].version=0x100;plan_fails();
    fixture();fixture_info[0].reserved=1;plan_fails();
    fixture();fixture_info[0].vcd=16;plan_fails();
    fixture();fixture_info[0].address=0x40040;plan_fails();
    fixture();fixture_info[0].address++;plan_fails();
    fixture();fixture_info[1].address=fixture_info[0].address;plan_fails();
    fixture();fixture_info[5].unit=2;plan_fails();
    fixture();fixture_info[5].width=1;plan_fails();
    fixture();CHECK(!sweet_rpmh_crypto_bw() && rh_crypto_held && !rh_poisoned && !rh_lock);
    CHECK(triggers==1 && captured_wait==0x3b && regs[RH_IRQ_EN/4]==3 && regs[RH_ENABLE/4]==0);
    for(unsigned i=0;i<6;i++)CHECK(captured_addr[i]==addresses[i] && captured_data[i]==data[i]);
    CHECK(!sweet_rpmh_crypto_bw() && triggers==1);
    fixture();mode=1;CHECK(sweet_rpmh_crypto_bw()==ETIMEDOUT && rh_poisoned && !rh_lock && !rh_crypto_held);
    CHECK(regs[RH_ENABLE/4]==0x3f && regs[RH_IRQ_EN/4]==2 && ticks==RH_TIMEOUT_US);
    unsigned old_writes=writes;CHECK(sweet_rpmh_crypto_bw()==EIO && writes==old_writes);
    fixture();mode=2;for(unsigned i=0;i<6;i++)regs[(RH_CMD_STATUS+i*RH_CMD_STRIDE)/4]=RH_ISSUED|RH_COMPLETE;
    CHECK(sweet_rpmh_crypto_bw()==ETIMEDOUT && rh_poisoned);
    fixture();mode=3;CHECK(sweet_rpmh_crypto_bw()==ETIMEDOUT && rh_poisoned);
    fixture();fail_offset=RH_DATA;CHECK(sweet_rpmh_crypto_bw()==EIO && rh_poisoned && !triggers);
    fixture();rh_ncpt=4;CHECK(sweet_rpmh_crypto_bw()==EINVAL && !writes);
    fixture();lookup_error=ENODEV;CHECK(sweet_rpmh_crypto_bw()==ENODEV && !writes);
    fixture();map_error=EIO;CHECK(sweet_rpmh_crypto_bw()==EIO && !writes && !rh_lock);
    fixture();rh_lock=1;CHECK(sweet_rpmh_crypto_bw()==EBUSY && !writes && rh_lock==1);
    fixture();regs[(RH_TCS_STRIDE+RH_ENABLE)/4]=1;
    regs[(RH_TCS_STRIDE+RH_ADDR)/4]=0x500a0;
    CHECK(sweet_rpmh_crypto_bw()==EBUSY && !writes && !rh_poisoned);
    fixture();regs[RH_ENABLE/4]=regs[(RH_TCS_STRIDE+RH_ENABLE)/4]=1;
    CHECK(sweet_rpmh_crypto_bw()==EBUSY && !writes);
    fixture();regs[(RH_TCS_STRIDE+RH_ENABLE)/4]=1;
    regs[(RH_TCS_STRIDE+RH_ADDR)/4]=0x40000;regs[RH_IRQ_STATUS/4]=2;
    CHECK(!sweet_rpmh_crypto_bw() && regs[RH_IRQ_STATUS/4]==2 && regs[(RH_TCS_STRIDE+RH_ENABLE)/4]==1);
    fixture();CHECK(!sweet_rpmh_vreg_enable("ldoc11",3000));
    CHECK(captured_addr[0]==0x40040 && captured_data[0]==3000);
    CHECK(captured_addr[1]==0x40048 && captured_data[1]==7);
    CHECK(captured_addr[2]==0x40044 && captured_data[2]==1 && captured_wait==7);
    fixture();regs[(RH_TCS_STRIDE+RH_ENABLE)/4]=1;
    regs[(RH_TCS_STRIDE+RH_ADDR)/4]=0x4004c;
    CHECK(sweet_rpmh_vreg_enable("ldoc11",3000)==EBUSY && !writes);
    fixture();CHECK(sweet_rpmh_vreg_enable("other",3000)==EINVAL && !writes);
    fixture();CHECK(rh_send_commands(NULL,6,0)==EINVAL && !writes);
    CHECK(rh_send_commands(cmds,0,0)==EINVAL && !writes);
    CHECK(rh_send_commands(cmds,6,0x40)==EINVAL && !writes);
    CHECK(rh_bcm_div(1,2)==1 && rh_bcm_div(0,2)==0 && rh_bcm_div(5,2)==2);
    puts("Crypto bandwidth tests: vote vectors, descriptor rejection, TCS completion/failure, LDO regression passed");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='sweet-crypto-test-') as tmp:
        d = Path(tmp)
        source = reconstruct(d)
        defines = '\n'.join(re.findall(r'^#define RH_.*$', source, re.M))
        transport = source[source.index('static bool\nrh_free('):source.index('/*\n * Read-only:')]
        policy = source[source.index('static bool rh_crypto_held;'):source.rindex('#endif')]
        c = d / 'test.c'
        c.write_text(PRELUDE + defines + '\n' + transport + policy + MODEL)
        exe = d / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-I', str(d / 'bsd/dev'), str(c), '-o', str(exe)], check=True)
        result = subprocess.run([str(exe)], check=True, text=True, capture_output=True)
        print(result.stdout.splitlines()[-1])


if __name__ == '__main__':
    main()
