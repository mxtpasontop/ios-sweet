#!/usr/bin/env python3
"""Exercise actual halted CP setup against a register model, with fault injection."""
from pathlib import Path
import importlib.util
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cp_memory', ROOT / 'tools/test-cp-memory.py')
memory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(memory)

CORE = r'''
static _Alignas(8) uint32_t core[GPU_SIZE/4];
static unsigned core_writes,drop_reg;
static bool gpu_map_fail,halt_fail;
static bool core_address(uintptr_t a){return a>=(uintptr_t)core && a<(uintptr_t)core+sizeof(core);}
static void core_write(uintptr_t a,uint32_t value){
    unsigned reg=(a-(uintptr_t)core)/4;CHECK(!(a&3));core_writes++;
    if(reg==A6XX_CP_SQE_CNTL){CHECK(value==3);if(!halt_fail)core[reg]=3;return;}
    CHECK(core[A6XX_CP_SQE_CNTL]==3);
    switch(reg){
    case A6XX_CP_ROQ_THRESHOLDS_2: case A6XX_CP_ROQ_THRESHOLDS_1:
    case A6XX_CP_MEM_POOL_SIZE: case A6XX_CP_AHB_CNTL:
    case A6XX_CP_RB_RPTR_ADDR_LO: case A6XX_CP_RB_RPTR_ADDR_HI:
    case A6XX_CP_RB_CNTL: case A6XX_CP_RB_BASE: case A6XX_CP_RB_BASE_HI:
    case A6XX_CP_SQE_INSTR_BASE_LO: case A6XX_CP_SQE_INSTR_BASE_LO+1: break;
    default: CHECK(!"unexpected CP write (including WPTR or engine start)");
    }
    core[reg]=drop_reg==reg?(value^1):value;
}
static bool gpu_poll(vm_offset_t base,uint32_t off,uint32_t mask,uint32_t want,unsigned us){
    CHECK(base==(uintptr_t)core && off==A6XX_CP_SQE_CNTL*4 && mask==3 && want==3 && us==1000);
    return (gpu_rd(base,off)&mask)==want;
}
'''

MAIN = r'''
static void cp_fixture(void){
    fixture();CHECK(gpu_cp_memory_setup());writes=0;
    memset(core,0,sizeof(core));core_writes=0;drop_reg=0;gpu_map_fail=halt_fail=false;
}
int main(void){
    cp_fixture();CHECK(gpu_cp_configure_halted());
    CHECK(!writes && core_writes==12 && core[A6XX_CP_SQE_CNTL]==3);
    CHECK(core[A6XX_CP_RB_BASE]==0x40000000 && core[A6XX_CP_SQE_INSTR_BASE_LO]==0x40010000);
    CHECK(core[A6XX_CP_RB_RPTR_ADDR_LO]==0x40020000 && core[A6XX_CP_RB_CNTL]==0x0800020c);
    CHECK(!core[A6XX_CP_RB_RPTR] && !core[A6XX_CP_RB_WPTR]);
    unsigned before=core_writes;CHECK(gpu_cp_post_pas_check() && core_writes==before && !writes);
    const unsigned changed[]={A6XX_CP_SQE_CNTL,A6XX_CP_ROQ_THRESHOLDS_2,A6XX_CP_RB_BASE,
        A6XX_CP_SQE_INSTR_BASE_LO,A6XX_CP_RB_BASE_HI,A6XX_CP_SQE_INSTR_BASE_LO+1,
        A6XX_CP_RB_RPTR,A6XX_CP_RB_WPTR,A6XX_CP_HW_FAULT,A6XX_CP_INTERRUPT_STATUS};
    for(unsigned i=0;i<sizeof(changed)/sizeof(changed[0]);i++){
        cp_fixture();CHECK(gpu_cp_configure_halted());core[changed[i]]^=1;before=core_writes;
        CHECK(!gpu_cp_post_pas_check() && core_writes==before && !writes);
    }
    cp_fixture();CHECK(gpu_cp_configure_halted());hw[SMMU_SMR(CP_SMR)/4]=0;
    before=core_writes;CHECK(!gpu_cp_post_pas_check() && core_writes==before && !writes);
    cp_fixture();cp_memory=0;CHECK(!gpu_cp_configure_halted() && !core_writes && !writes);
    cp_fixture();map_fail=true;CHECK(!gpu_cp_configure_halted() && !core_writes && !writes);
    cp_fixture();gpu_map_fail=true;CHECK(!gpu_cp_configure_halted() && !core_writes && !writes);
    const unsigned context[]={SMMU_CB(CP_CB)+SMMU_CB_SCTLR,SMMU_CB(CP_CB)+SMMU_CB_TCR,
        SMMU_CB(CP_CB)+SMMU_CB_TTBCR2,SMMU_CB(CP_CB)+SMMU_CB_TTBR0,SMMU_CB(CP_CB)+SMMU_CB_TTBR0+4,
        SMMU_CB(CP_CB)+SMMU_CB_MAIR0,SMMU_CB(CP_CB)+SMMU_CB_MAIR1,
        SMMU_GR1+SMMU_CBA2R(CP_CB),SMMU_GR1+SMMU_CBAR(CP_CB),
        SMMU_SMR(CP_SMR),SMMU_S2CR(CP_SMR),SMMU_SMR(0),SMMU_SMR(1),SMMU_S2CR(0),SMMU_S2CR(1)};
    for(unsigned i=0;i<sizeof(context)/sizeof(context[0]);i++){
        cp_fixture();unsigned bit=context[i]==SMMU_GR1+SMMU_CBAR(CP_CB)?0x10000:1;
        hw[context[i]/4]^=bit;CHECK(!gpu_cp_configure_halted() && !writes && !core_writes);
    }
    cp_fixture();hw[(SMMU_CB(CP_CB)+SMMU_CB_FSR)/4]=0x402;CHECK(!gpu_cp_configure_halted() && !core_writes);
    cp_fixture();hw[SMMU_sGFSR/4]=1;CHECK(!gpu_cp_configure_halted() && !core_writes);
    cp_fixture();cp_write64(cp_memory,CP_L3,0);CHECK(!gpu_cp_configure_halted() && !core_writes);
    cp_fixture();halt_fail=true;CHECK(!gpu_cp_configure_halted() && core_writes==1 && !writes);
    const unsigned inherited[]={A6XX_CP_RB_BASE,A6XX_CP_RB_BASE_HI,A6XX_CP_SQE_INSTR_BASE_LO,
        A6XX_CP_SQE_INSTR_BASE_LO+1,A6XX_CP_RB_RPTR,A6XX_CP_RB_WPTR};
    for(unsigned i=0;i<sizeof(inherited)/sizeof(inherited[0]);i++){
        cp_fixture();core[inherited[i]]=1;CHECK(!gpu_cp_configure_halted() && core_writes==1 && !writes);
    }
    const unsigned readbacks[]={A6XX_CP_ROQ_THRESHOLDS_2,A6XX_CP_ROQ_THRESHOLDS_1,
        A6XX_CP_MEM_POOL_SIZE,A6XX_CP_AHB_CNTL,A6XX_CP_RB_RPTR_ADDR_LO,A6XX_CP_RB_RPTR_ADDR_HI,
        A6XX_CP_RB_CNTL,A6XX_CP_RB_BASE,A6XX_CP_RB_BASE_HI,A6XX_CP_SQE_INSTR_BASE_LO,A6XX_CP_SQE_INSTR_BASE_LO+1};
    for(unsigned i=0;i<sizeof(readbacks)/sizeof(readbacks[0]);i++){
        cp_fixture();drop_reg=readbacks[i];CHECK(!gpu_cp_configure_halted() && !writes);
    }
    cp_fixture();core[A6XX_CP_HW_FAULT]=1;CHECK(!gpu_cp_configure_halted() && !writes);
    cp_fixture();core[A6XX_CP_INTERRUPT_STATUS]=1;CHECK(!gpu_cp_configure_halted() && !writes);
    cp_fixture();hw[(SMMU_CB(CP_CB)+SMMU_CB_FSR)/4]=0x400;CHECK(gpu_cp_configure_halted());
    free(storage);
    puts("Halted CP tests: context, halt, inherited work, all register readbacks, faults and read-only post-PAS comparison passed; no engine/WPTR writes");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='sweet-cp-halted-') as tmp:
        d = Path(tmp)
        (d / 'bsd/dev').mkdir(parents=True)
        for patch in sorted((ROOT / 'xnu/patches').glob('*.patch')):
            chunks = re.split(r'(?=^--- )', patch.read_text(errors='replace'), flags=re.M)
            chosen = [s for s in chunks if re.search(r'^\+\+\+ b/bsd/dev/sweet_gpu.c$', s, re.M)]
            if chosen:
                subprocess.run(['patch', '--batch', '--fuzz=0', '-s', '-p1'], cwd=d,
                               input=''.join(chosen), text=True, check=True)
        src = (d / 'bsd/dev/sweet_gpu.c').read_text()
        defines = '\n'.join(re.findall(r'^#define .*$', src.replace('\\\n', ''), re.M))
        body = src[src.index('/* CP memory stage:'):src.index('/* End CP memory stage. */')]
        halted = src[src.index('/* Halted register stage.'):src.index('/* End halted CP register stage. */')]
        halted += src[src.index('/* Read-only post-PAS comparison.'):src.index('/* End post-PAS CP comparison. */')]
        body = re.sub(r'__asm__ volatile\s*\("[^"]*"\s*:::\s*"memory"\);', '', body)
        model = memory.MODEL[:memory.MODEL.index('int main(')]
        model = model.replace('CHECK(pa==SMMU_PA && size==SMMU_SIZE);',
                              'if(pa==GPU_PA){CHECK(size==GPU_SIZE);return gpu_map_fail?0:(uintptr_t)core;}CHECK(pa==SMMU_PA && size==SMMU_SIZE);')
        model = model.replace('uintptr_t a=base+off;CHECK(',
                              'uintptr_t a=base+off;if(core_address(a))return *(uint32_t*)a;CHECK(', 1)
        model = model.replace('uintptr_t a=base+off;unsigned absolute=',
                              'uintptr_t a=base+off;if(core_address(a)){core_write(a,value);return;}unsigned absolute=', 1)
        c = d / 'test.c'
        c.write_text(memory.PRELUDE + defines + '\n' + CORE + body + halted + model + MAIN)
        exe = d / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-format', '-Wno-unused-function', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', str(c), '-o', str(exe)], check=True)
        result = subprocess.run([str(exe)], check=True, text=True, capture_output=True)
        print(result.stdout.splitlines()[-1])


if __name__ == '__main__':
    main()
