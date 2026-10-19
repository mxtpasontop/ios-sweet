#!/usr/bin/env python3
"""Test actual 0091 loader code with fake memory/SMC; no authentication claimed."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def source(directory):
    (directory / 'bsd/dev').mkdir(parents=True)
    for patch in sorted((ROOT / 'xnu/patches').glob('*.patch')):
        sections = re.split(r'(?=^--- )', patch.read_text(errors='replace'), flags=re.M)
        selected = [s for s in sections if re.search(r'^\+\+\+ b/bsd/dev/sweet_scm.c$', s, re.M)]
        if selected:
            subprocess.run(['patch', '--batch', '--fuzz=0', '-s', '-p1'], cwd=directory,
                           input=''.join(selected), text=True, check=True)
    return (directory / 'bsd/dev/sweet_scm.c').read_text()


PRELUDE = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);abort();} } while(0)
#define PAGE_SHIFT 14
#define PAGE_SIZE (1u<<PAGE_SHIFT)
#define KERN_SUCCESS 0
#define KMA_DATA 1
#define KMA_ZERO 2
#define KMA_PERMANENT 4
#define VM_KERN_MEMORY_IOKIT 9
#define VM_WIMG_WCOMB 7
#define TRUE 1
#define kSuccess 0
#define kernel_map 1
#define kernel_pmap 2
#define ptoa_64(pn) ((uint64_t)(pn)<<PAGE_SHIFT)
typedef uintptr_t vm_offset_t;
typedef size_t vm_size_t;
typedef uint64_t addr64_t;
typedef uint32_t ppnum_t;
typedef void *DTEntry;
static uint8_t metadata[6860],code_blob[1984];
static unsigned metadata_size=sizeof(metadata),code_size=sizeof(code_blob);
static uint8_t *memory;
static unsigned allocations,cache_changes,smcs,phase_count[8],syncs;
static unsigned fail_cmd,fail_kind,interrupt_cmd,busy_cmd;
static bool allocation_fails,bad_alignment,bad_contiguous,missing,protected_memory;
static const uint64_t fake_pa=0x100200000ULL;
static void sweet_log_sync(void) {syncs++;}
static void delay(unsigned us){CHECK(us==30000);}
static int SecureDTLookupEntry(void *unused,const char *name,DTEntry *entry) {
    CHECK(!unused && !strcmp(name,"/sweet-gpu"));*entry=(void*)1;return missing?-1:0;
}
static int SecureDTGetProperty(DTEntry node,const char *name,const void **data,unsigned *size) {
    CHECK(node==(void*)1);
    if(!strcmp(name,"zap-metadata")){*data=metadata;*size=metadata_size;return 0;}
    CHECK(!strcmp(name,"zap-code"));*data=code_blob;*size=code_size;return 0;
}
static int kmem_alloc_contig(unsigned map,vm_offset_t *kva,size_t bytes,uintptr_t mask,
    ppnum_t max,ppnum_t pn_mask,unsigned flags,unsigned tag) {
    CHECK(map==kernel_map && bytes==0x100000+PAGE_SIZE && mask==0xfffff && max==0);
    CHECK(pn_mask==63 && flags==(KMA_DATA|KMA_ZERO|KMA_PERMANENT) && tag==VM_KERN_MEMORY_IOKIT);
    allocations++;if(allocation_fails)return -1;
    memory=aligned_alloc(0x100000,0x200000);CHECK(memory);memset(memory,0,0x200000);
    *kva=(uintptr_t)memory;return 0;
}
static ppnum_t pmap_find_phys(unsigned map,addr64_t va) {
    CHECK(map==kernel_pmap && va>=(uintptr_t)memory && va<(uintptr_t)memory+0x104000);
    ppnum_t pn=(fake_pa>>PAGE_SHIFT)+((va-(uintptr_t)memory)>>PAGE_SHIFT);
    return pn+(bad_alignment?1:0)+(bad_contiguous && va==(uintptr_t)memory+PAGE_SIZE?1:0);
}
static void pmap_set_cache_attributes(ppnum_t pn,unsigned flags) {
    CHECK(pn==(fake_pa>>PAGE_SHIFT)+cache_changes && flags==VM_WIMG_WCOMB);cache_changes++;
}
static void flush_dcache64(addr64_t pa,size_t bytes,int physical) {
    CHECK(pa==fake_pa && bytes==0x104000 && physical==TRUE && cache_changes==65);
}
'''

MODEL = r'''
static unsigned pending;
static void scm_smccc(struct scm_regs *r) {
    unsigned cmd=(unsigned)r->a[0]&0xff;
    if(r->a[0]==1){CHECK(pending && r->a[6]==0xabc);cmd=pending;pending=0;}
    else {
        CHECK(r->a[0]==(SCM_64|SCM_SIP|0x200|cmd));
        CHECK(r->a[2]==13 && r->a[5]==0 && r->a[6]==0);
    }
    CHECK(cmd==1 || cmd==2 || cmd==5 || cmd==6);smcs++;phase_count[cmd]++;
    CHECK(syncs && cache_changes==65);
    if(cmd==1){CHECK(r->a[1]==0x82 && r->a[3]==fake_pa+0x100000 && !r->a[4]);
        CHECK(!memcmp(memory+0x100000,metadata,metadata_size));}
    if(cmd==2){CHECK(r->a[1]==3 && r->a[3]==fake_pa && r->a[4]==0x1000);
        for(unsigned i=0;i<0x100000;i++)CHECK(memory[i]==0);}
    if(cmd==5){CHECK(r->a[1]==1 && !r->a[3] && !r->a[4]);
        CHECK(!memcmp(memory,code_blob,code_size));}
    if(cmd==6)CHECK(r->a[1]==1 && !r->a[3] && !r->a[4]);
    if(cmd==busy_cmd){r->a[0]=0xfffffff4;return;}
    if(cmd==interrupt_cmd && phase_count[cmd]==1){r->a[0]=1;r->a[6]=0xabc;pending=cmd;return;}
    r->a[0]=(cmd==fail_cmd && fail_kind==1)?0xfffffffc:0;
    r->a[1]=(cmd==fail_cmd && fail_kind==2)?0xfffffffe:0;
    if(cmd==5 && cmd!=fail_cmd){CHECK(!mprotect(memory,0x100000,PROT_NONE));protected_memory=true;}
}
static void put16(unsigned off,unsigned v){metadata[off]=v;metadata[off+1]=v>>8;}
static void put32(unsigned off,uint32_t v){put16(off,v);put16(off+2,v>>16);}
static void fixture(void) {
    if(protected_memory){CHECK(!mprotect(memory,0x100000,PROT_READ|PROT_WRITE));protected_memory=false;}
    free(memory);memory=NULL;memset(metadata,0,sizeof(metadata));memset(code_blob,0xa5,sizeof(code_blob));
    metadata_size=sizeof(metadata);code_size=sizeof(code_blob);
    allocations=cache_changes=smcs=syncs=pending=0;memset(phase_count,0,sizeof(phase_count));
    allocation_fails=bad_alignment=bad_contiguous=missing=false;
    fail_cmd=fail_kind=interrupt_cmd=busy_cmd=0;scm_zap_ready=true;scm_zap_attempted=false;
    put32(0,0x464c457f);metadata[4]=metadata[5]=metadata[6]=1;
    put16(16,2);put16(18,164);put32(20,1);put32(24,0x5000);put32(28,52);
    put16(40,52);put16(42,32);put16(44,3);
    put32(52+16,148);
    put32(84+4,0x1000);put32(84+12,0x6000);put32(84+16,sizeof(metadata)-148);
    put32(84+20,0x2000);put32(84+24,0x02200000);
    put32(116,1);put32(116+4,0x3000);put32(116+12,0x5000);put32(116+16,sizeof(code_blob));
    put32(116+20,sizeof(code_blob));put32(116+24,0x08000007);put32(116+28,0x100000);
}
int main(int argc,char **argv) {
    fixture();CHECK(zap_valid(metadata,sizeof(metadata),code_blob,sizeof(code_blob)));
    for(unsigned n=0;n<=148;n++)CHECK(!zap_valid(metadata,n,code_blob,sizeof(code_blob)));
    CHECK(!zap_valid(NULL,sizeof(metadata),code_blob,sizeof(code_blob)));
    CHECK(!zap_valid(metadata,sizeof(metadata),NULL,sizeof(code_blob)));
    CHECK(!zap_valid(metadata,8193,code_blob,sizeof(code_blob)));
    CHECK(!zap_valid(metadata,sizeof(metadata),code_blob,4097));
    unsigned corrupt[]={0,4,5,6,16,18,20,24,28,40,42,44,52,56,68,72,84,88,96,100,104,108,116,120,128,132,136,140,144};
    for(unsigned i=0;i<sizeof(corrupt)/sizeof(corrupt[0]);i++) {
        fixture();metadata[corrupt[i]]^=1;CHECK(!sweet_scm_gpu_zap_test() || (!allocations && !smcs));
        CHECK(!allocations && !smcs);
    }
    fixture();CHECK(sweet_scm_gpu_zap_test() && smcs==4 && phase_count[6]==1);
    CHECK(!sweet_scm_gpu_zap_test() && smcs==4);
    for(unsigned cmd=1;cmd<=6;cmd++)if(cmd==1 || cmd==2 || cmd==5 || cmd==6) {
        for(unsigned kind=1;kind<=2;kind++) {
            fixture();fail_cmd=cmd;fail_kind=kind;
            CHECK(sweet_scm_gpu_zap_test()==(cmd!=6));
            CHECK(phase_count[6]==(cmd!=1));
            if(cmd==1)CHECK(smcs==1);
            if(cmd==2)CHECK(!phase_count[5]);
        }
    }
    fixture();busy_cmd=1;CHECK(!sweet_scm_gpu_zap_test() && smcs==4 && !phase_count[6]);
    fixture();busy_cmd=5;CHECK(!sweet_scm_gpu_zap_test() && !phase_count[6]);
    fixture();interrupt_cmd=1;CHECK(sweet_scm_gpu_zap_test() && smcs==5);
    fixture();interrupt_cmd=5;CHECK(sweet_scm_gpu_zap_test() && smcs==5);
    fixture();scm_zap_ready=false;CHECK(sweet_scm_gpu_zap_test() && !allocations && !smcs);
    fixture();missing=true;CHECK(sweet_scm_gpu_zap_test() && !allocations && !smcs);
    fixture();allocation_fails=true;CHECK(sweet_scm_gpu_zap_test() && !smcs);
    fixture();bad_alignment=true;CHECK(sweet_scm_gpu_zap_test() && !smcs && !cache_changes);
    fixture();bad_contiguous=true;CHECK(sweet_scm_gpu_zap_test() && !smcs && !cache_changes);
    if(argc==3){
        fixture();FILE *f=fopen(argv[1],"rb");CHECK(f);metadata_size=fread(metadata,1,sizeof(metadata),f);fclose(f);
        f=fopen(argv[2],"rb");CHECK(f);code_size=fread(code_blob,1,sizeof(code_blob),f);fclose(f);
        CHECK(zap_valid(metadata,metadata_size,code_blob,code_size));
    }
    fixture();free(memory);
    puts("Zap loader tests: parser bounds, PAS ABI/ordering, failures, continuations, protected-memory retention passed");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='sweet-zap-test-') as tmp:
        d = Path(tmp)
        src = source(d)
        constants = src[src.index('#define SCM_SIP'):src.index('/* Preserve x6')]
        transport = src[src.index('static bool\nscm_invoke'):src.index('static bool\nscm_logged_query')]
        loader = src[src.index('static bool scm_zap_ready'):src.index('\nvoid\nsweet_scm_probe')]
        loader = loader.replace('__asm__ volatile("dsb sy" ::: "memory");', '')
        c = d / 'test.c'
        c.write_text(PRELUDE + constants + '\nstatic void scm_smccc(struct scm_regs *);\n' + transport + loader + MODEL)
        exe = d / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-Wno-format', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', str(c), '-o', str(exe)], check=True)
        args = [str(exe)]
        fw = ROOT / 'research/gpu/fw'
        if (fw / 'a615_zap.mdt').exists() and (fw / 'a615_zap.b02').exists():
            args += [str(fw / 'a615_zap.mdt'), str(fw / 'a615_zap.b02')]
        result = subprocess.run(args, check=True, capture_output=True, text=True)
        print(result.stdout.splitlines()[-1])


if __name__ == '__main__':
    main()
