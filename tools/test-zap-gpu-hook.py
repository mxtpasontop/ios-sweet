#!/usr/bin/env python3
"""Check the actual GPU OOB -> PAS -> slumber connection using a host model."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define OOB_GPU 0
#define OOB_BOOT_SLUMBER 6
#define GDSC_PWR_ON (1u<<31)
#define CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);abort();} } while(0)
static bool ack,powered,stopped,configured;
static unsigned calls,clears,slumbers,reports,syncs,configs;
static bool gmu_oob_set(unsigned req,const char *name){CHECK(req==0 && !strcmp(name,"gpu"));return ack;}
static bool gpu_report(uint32_t *v){reports++;*v=powered?GDSC_PWR_ON:0;return true;}
static void gpu_report_gmu(uint32_t v){CHECK(v==(powered?GDSC_PWR_ON:0));}
static void sweet_log_sync(void){syncs++;}
static bool sweet_scm_gpu_zap_test(void){CHECK(ack && powered && !clears && !slumbers);calls++;return stopped;}
static bool gpu_cp_configure_halted(void){CHECK(ack && powered && calls==1 && stopped && !clears && !slumbers);configs++;return configured;}
static void gmu_oob_clear(unsigned req){CHECK(req==(clears?OOB_BOOT_SLUMBER:OOB_GPU));clears++;}
static void gpu_gx_slumber(void){CHECK(clears==2);slumbers++;}
'''
MAIN = r'''
static void fixture(void){ack=powered=stopped=configured=true;calls=clears=slumbers=reports=syncs=configs=0;}
int main(void){
    fixture();CHECK(gpu_gx_test(true,false) && calls==1 && !configs && clears==2 && slumbers==1);
    fixture();CHECK(gpu_gx_test(false,false) && !calls && !configs && clears==2 && slumbers==1);
    fixture();stopped=false;CHECK(!gpu_gx_test(true,false) && calls==1 && !configs && !clears && !slumbers && syncs==2);
    fixture();ack=false;CHECK(gpu_gx_test(true,true) && !calls && !configs && clears==2 && slumbers==1);
    fixture();powered=false;CHECK(gpu_gx_test(true,true) && !calls && !configs && clears==2 && slumbers==1);
    fixture();CHECK(gpu_gx_test(true,true) && calls==1 && configs==1 && clears==2 && slumbers==1);
    fixture();configured=false;CHECK(!gpu_gx_test(true,true) && calls==1 && configs==1 && !clears && !slumbers);
    fixture();stopped=false;CHECK(!gpu_gx_test(true,true) && calls==1 && !configs && !clears && !slumbers);
    puts("GPU zap/CP hooks: mode gates, powered PAS -> halted CP order, failures retaining power passed");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='sweet-zap-hook-') as tmp:
        d = Path(tmp)
        (d / 'bsd/dev').mkdir(parents=True)
        for patch in sorted((ROOT / 'xnu/patches').glob('*.patch')):
            sections = re.split(r'(?=^--- )', patch.read_text(errors='replace'), flags=re.M)
            chosen = [s for s in sections if re.search(r'^\+\+\+ b/bsd/dev/sweet_gpu.c$', s, re.M)]
            if chosen:
                subprocess.run(['patch', '--batch', '--fuzz=0', '-s', '-p1'], cwd=d,
                               input=''.join(chosen), text=True, check=True)
        src = (d / 'bsd/dev/sweet_gpu.c').read_text()
        func = src[src.index('static bool\ngpu_gx_test('):src.index('/* Nothing services the GMU')]
        assert 'gpu_gx_test(mode >= 7, mode >= 9)' in src
        c = d / 'test.c'
        c.write_text(PRELUDE + func + MAIN)
        exe = d / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(c), '-o', str(exe)], check=True)
        result = subprocess.run([str(exe)], check=True, text=True, capture_output=True)
        print(result.stdout.splitlines()[-1])


if __name__ == '__main__':
    main()
