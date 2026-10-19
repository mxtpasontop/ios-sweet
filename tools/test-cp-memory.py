#!/usr/bin/env python3
"""Host checks of the actual CP memory stage; no hardware translation claimed."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);abort();}}while(0)
#define PAGE_SHIFT 14
#define PAGE_SIZE 0x4000u
#define PAGE_MASK 0x3fffu
#define kernel_map 1
#define kernel_pmap 2
#define KMA_DATA 1
#define KMA_ZERO 2
#define KMA_PERMANENT 4
#define VM_KERN_MEMORY_IOKIT 9
#define VM_WIMG_WCOMB 7
#define TRUE 1
#define KERN_SUCCESS 0
#define kSuccess 0
#define ptoa_64(pn) ((uint64_t)(pn)<<PAGE_SHIFT)
typedef uintptr_t vm_offset_t;
typedef uint64_t addr64_t;
typedef uint32_t ppnum_t;
typedef void *DTEntry;
static _Alignas(8) uint32_t hw[0x10000/4];
static uint8_t firmware[0x8004],*storage;
static unsigned firmware_size,allocations,cache_pages,writes,syncs;
static bool missing,map_fail,alloc_fail,noncontiguous,drop_sctlr,drop_smr,tlb_fail;
static const uint64_t fake_pa=0x105800000ULL;
static int SecureDTLookupEntry(void *unused,const char *path,DTEntry *node){
    CHECK(!unused && !strcmp(path,"/sweet-gpu"));*node=(void*)1;return missing?-1:0;
}
static int SecureDTGetProperty(DTEntry node,const char *name,const void **ptr,unsigned *size){
    CHECK(node==(void*)1 && !strcmp(name,"sqe-firmware"));*ptr=firmware;*size=firmware_size;return 0;
}
static int kmem_alloc_contig(unsigned map,vm_offset_t *va,size_t size,uintptr_t mask,
    ppnum_t max,ppnum_t pn_mask,unsigned flags,unsigned tag){
    CHECK(map==kernel_map && size==0x20000 && mask==PAGE_MASK && !max && !pn_mask);
    CHECK(flags==(KMA_DATA|KMA_ZERO|KMA_PERMANENT) && tag==VM_KERN_MEMORY_IOKIT);
    allocations++;if(alloc_fail)return -1;
    storage=aligned_alloc(PAGE_SIZE,size);CHECK(storage);memset(storage,0,size);*va=(uintptr_t)storage;return 0;
}
static ppnum_t pmap_find_phys(unsigned map,addr64_t va){
    CHECK(map==kernel_pmap && va>=(uintptr_t)storage && va<(uintptr_t)storage+0x20000);
    unsigned index=(va-(uintptr_t)storage)>>PAGE_SHIFT;
    return (fake_pa>>PAGE_SHIFT)+index+(noncontiguous && index==1?1:0);
}
static void pmap_set_cache_attributes(ppnum_t pn,unsigned flags){
    CHECK(pn==(fake_pa>>PAGE_SHIFT)+cache_pages && flags==VM_WIMG_WCOMB);cache_pages++;
}
static void flush_dcache64(addr64_t pa,size_t size,int physical){CHECK(pa==fake_pa && size==0x20000 && physical && cache_pages==8);}
static vm_offset_t ml_io_map(vm_offset_t pa,size_t size);
static uint32_t gpu_rd(vm_offset_t base,uint32_t off);
static void gpu_wr(vm_offset_t base,uint32_t off,uint32_t value);
static bool smmu_sync(vm_offset_t base,uint32_t sync,uint32_t status);
static void smmu_write_sme(vm_offset_t base,unsigned idx,uint32_t s2cr,uint32_t smr,const char *name);
static void sweet_log_sync(void){syncs++;}
'''
MODEL = r'''
static vm_offset_t ml_io_map(vm_offset_t pa,size_t size){CHECK(pa==SMMU_PA && size==SMMU_SIZE);return map_fail?0:(uintptr_t)hw;}
static uint32_t gpu_rd(vm_offset_t base,uint32_t off){
    uintptr_t a=base+off;CHECK(a>=(uintptr_t)hw && a<(uintptr_t)hw+sizeof(hw) && !(a&3));
    return *(uint32_t*)a;
}
static void gpu_wr(vm_offset_t base,uint32_t off,uint32_t value){
    uintptr_t a=base+off;unsigned absolute=a-(uintptr_t)hw;
    CHECK(a>=(uintptr_t)hw && a<(uintptr_t)hw+sizeof(hw) && !(a&3));
    CHECK(absolute!=SMMU_MICRO_MMU_CTRL && absolute!=SMMU_CB(CP_CB)+0x800 && absolute!=SMMU_CB(CP_CB)+0x8f0);
    writes++;
    if(drop_sctlr && absolute==SMMU_CB(CP_CB)+SMMU_CB_SCTLR)return;
    if(drop_smr && absolute==SMMU_SMR(CP_SMR))return;
    if(absolute==SMMU_CB(CP_CB)+SMMU_CB_FSR){hw[absolute/4]&=~(value&0xc00001feu);return;}
    *(uint32_t*)a=value;
}
static bool smmu_sync(vm_offset_t base,uint32_t sync,uint32_t status){
    CHECK((base==(uintptr_t)hw+SMMU_CB(CP_CB) && sync==SMMU_CB_TLBSYNC && status==SMMU_CB_TLBSTATUS) ||
          (base==(uintptr_t)hw && sync==SMMU_sTLBGSYNC && status==SMMU_sTLBGSTATUS));return !tlb_fail;
}
static void smmu_write_sme(vm_offset_t base,unsigned idx,uint32_t s2cr,uint32_t smr,const char *name){
    CHECK(idx==2 && !strcmp(name,"CP user SID0"));gpu_wr(base,SMMU_S2CR(idx),s2cr);gpu_wr(base,SMMU_SMR(idx),smr);
}
static void put32(unsigned off,uint32_t value){memcpy(firmware+off,&value,4);}
static void fixture(void){
    free(storage);storage=NULL;cp_memory=cp_memory_pa=0;memset(hw,0,sizeof(hw));memset(firmware,0xa5,sizeof(firmware));
    missing=map_fail=alloc_fail=noncontiguous=drop_sctlr=drop_smr=tlb_fail=false;
    allocations=cache_pages=writes=syncs=0;firmware_size=256;put32(0,0);put32(4,0x190);put32(12,0);
    hw[SMMU_IDR0/4]=0x48016605;hw[SMMU_SMR(0)/4]=SMR_VALID|5;hw[SMMU_SMR(1)/4]=SMR_VALID|4;
    hw[SMMU_S2CR(0)/4]=hw[SMMU_S2CR(1)/4]=S2CR_TRANS_CB(0);
    hw[(SMMU_CB(0)+SMMU_CB_SCTLR)/4]=SCTLR_GMU;
}
int main(int argc,char **argv){
    fixture();CHECK(cp_fw_valid(firmware,firmware_size));
    for(unsigned n=0;n<16;n++)CHECK(!cp_fw_valid(firmware,n));
    CHECK(!cp_fw_valid(NULL,256) && !cp_fw_valid(firmware,0x8008) && !cp_fw_valid(firmware,17));
    put32(0,1);CHECK(!cp_fw_valid(firmware,256));put32(0,0);
    put32(4,0x18a);CHECK(!cp_fw_valid(firmware,256));put32(12,1);CHECK(cp_fw_valid(firmware,256));
    put32(4,0x189);CHECK(!cp_fw_valid(firmware,256));
    fixture();uint32_t cb0[0x1000/4];memcpy(cb0,hw+SMMU_CB(0)/4,sizeof(cb0));
    CHECK(gpu_cp_memory_setup() && allocations==1 && cache_pages==8);
    CHECK(!memcmp(cb0,hw+SMMU_CB(0)/4,sizeof(cb0)) && hw[SMMU_SMR(0)/4]==(SMR_VALID|5) && hw[SMMU_SMR(1)/4]==(SMR_VALID|4));
    CHECK(hw[SMMU_SMR(2)/4]==SMR_VALID && hw[SMMU_S2CR(2)/4]==S2CR_TRANS_CB(1));
    CHECK(!hw[SMMU_SMR(3)/4] && !hw[(SMMU_CB(2)+SMMU_CB_SCTLR)/4]);
    CHECK(!memcmp(storage+0xc000,firmware+4,firmware_size-4));
    uint64_t pa;CHECK(cp_walk(0x40000000,true,&pa) && pa==fake_pa+0x4000);
    CHECK(cp_walk(0x40017fff,false,&pa) && pa==fake_pa+0x13fff && !cp_walk(0x40010000,true,&pa));
    uint64_t *pte=(uint64_t*)(storage+CP_L3+8*16);uint64_t saved=*pte;
    *pte&=~(1ull<<7);CHECK(!cp_check_tables());*pte=saved;
    *pte&=~(1ull<<10);CHECK(!cp_check_tables());*pte=saved;
    uint64_t *guard=(uint64_t*)(storage+CP_L3+8*8);*guard=saved;CHECK(!cp_check_tables());*guard=0;
    uint64_t *l1=(uint64_t*)(storage+8);saved=*l1;*l1=(fake_pa+CP_MEMORY_SIZE)|PTE_TABLE;
    CHECK(!cp_walk(0x40000000,false,&pa));*l1=saved;
    fixture();missing=true;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();map_fail=true;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();put32(4,0x180);CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();hw[(SMMU_CB(1)+SMMU_CB_SCTLR)/4]=1;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();hw[(SMMU_CB(1)+SMMU_CB_TTBR0)/4]=0x1000;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();hw[SMMU_SMR(2)/4]=SMR_VALID|3;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();hw[SMMU_SMR(3)/4]=SMR_VALID;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();hw[SMMU_SMR(3)/4]=SMR_VALID|(1u<<16)|1;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();hw[SMMU_SMR(3)/4]=SMR_VALID|7;hw[SMMU_S2CR(3)/4]=S2CR_TRANS_CB(1);
    CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();hw[SMMU_IDR0/4]=4;CHECK(!gpu_cp_memory_setup() && !allocations && !writes);
    fixture();alloc_fail=true;CHECK(!gpu_cp_memory_setup() && !writes);
    fixture();noncontiguous=true;CHECK(!gpu_cp_memory_setup() && !writes && !cache_pages);
    fixture();drop_sctlr=true;CHECK(!gpu_cp_memory_setup() && !hw[SMMU_SMR(2)/4]);
    fixture();tlb_fail=true;CHECK(!gpu_cp_memory_setup() && !hw[SMMU_SMR(2)/4]);
    fixture();drop_smr=true;CHECK(!gpu_cp_memory_setup());
    if(argc==2){fixture();FILE *f=fopen(argv[1],"rb");CHECK(f);firmware_size=fread(firmware,1,sizeof(firmware),f);fclose(f);CHECK(gpu_cp_memory_setup());}
    fixture();free(storage);
    puts("CP memory tests: SQE versions, mappings/guards/permissions, ownership, readback and failure paths passed");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='sweet-cp-memory-') as tmp:
        d = Path(tmp)
        (d / 'bsd/dev').mkdir(parents=True)
        for patch in sorted((ROOT / 'xnu/patches').glob('*.patch')):
            chunks = re.split(r'(?=^--- )', patch.read_text(errors='replace'), flags=re.M)
            chosen = [s for s in chunks if re.search(r'^\+\+\+ b/bsd/dev/sweet_gpu.c$', s, re.M)]
            if chosen:
                subprocess.run(['patch', '--batch', '--fuzz=0', '-s', '-p1'], cwd=d,
                               input=''.join(chosen), text=True, check=True)
        src = (d / 'bsd/dev/sweet_gpu.c').read_text()
        require_hook = 'if (mode >= 8 && !gpu_cp_memory_setup())'
        assert src.count(require_hook) == 1
        defines = '\n'.join(re.findall(r'^#define .*$', src.replace('\\\n', ''), re.M))
        body = src[src.index('/* CP memory stage:'):src.index('/* End CP memory stage. */')]
        body = re.sub(r'__asm__ volatile\s*\("[^"]*"\s*:::\s*"memory"\);', '', body)
        c = d / 'test.c'
        c.write_text(PRELUDE + defines + '\n' + body + MODEL)
        exe = d / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-format', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(c), '-o', str(exe)], check=True)
        args = [str(exe)]
        firmware = ROOT / 'research/gpu/fw/a630_sqe.fw'
        if firmware.exists():
            args.append(str(firmware))
        result = subprocess.run(args, check=True, text=True, capture_output=True)
        print(result.stdout.splitlines()[-1])


if __name__ == '__main__':
    main()
