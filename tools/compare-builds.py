#!/usr/bin/env python3
"""Compare old/new kernels, require evidence of a change, verify boot payloads.

Example: compare-builds.py OLD_KERNEL NEW_KERNEL --old-boot OLD.img --new-boot NEW.img
  --added-call _gpu_gx_test:_sweet_scm_gpu_zap_test --report comparison.json

Different bytes alone do not prove a fix: supply a new call or diagnostic string,
and review the recorded disassembly for the intended behavior.
"""
import argparse
import difflib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

import mkpayload


def require(condition, message):
    if not condition:
        raise ValueError(message)


def boot_payload(path):
    data = Path(path).read_bytes()
    require(data[:8] == b'ANDROID!', f'{path}: not an Android boot image')
    kernel_size, _, payload_size = struct.unpack_from('<3I', data, 8)
    page = struct.unpack_from('<I', data, 36)[0]
    require(page >= 2048 and page & (page - 1) == 0, 'invalid boot page size')
    offset = page + (kernel_size + page - 1) // page * page
    require(offset + payload_size <= len(data), 'truncated boot payload')
    return data, data[offset:offset + payload_size]


def verify_payload(payload, kernel):
    require(payload[:8] == b'SWEETXNU', 'missing SWEET payload')
    version, count = struct.unpack_from('<II', payload, 8)
    require(version == 1 and 0 < count < 32, 'unsupported payload geometry')
    image = bytearray(kernel)
    macho = mkpayload.parse_macho(image)
    mkpayload.apply_chained_fixups(image, macho)
    segments = [s for s in macho['segs'] if s['vmsize']]
    require(count >= len(segments), 'missing payload segments')
    for i, segment in enumerate(segments):
        va, size, offset, file_size = struct.unpack_from('<4Q', payload, mkpayload.SEG_TABLE + i * 32)
        require((va, size, file_size) == (segment['vmaddr'], segment['vmsize'], segment['filesize']),
                f"payload geometry differs for {segment['name']}")
        expected = image[segment['fileoff']:segment['fileoff'] + file_size]
        require(payload[offset:offset + file_size] == expected,
                f"packaged {segment['name']} does not match this kernel")
    return len(segments)


def disassemble(tool, path, symbol):
    result = subprocess.run([tool, '--disassemble-symbols=' + symbol,
                             '--no-show-raw-insn', '--symbolize-operands', str(path)],
                            check=True, capture_output=True, text=True)
    require(f'<{symbol}>:' in result.stdout, f'{path}: missing function {symbol}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('old_kernel', type=Path)
    parser.add_argument('new_kernel', type=Path)
    parser.add_argument('--old-boot', type=Path)
    parser.add_argument('--new-boot', type=Path)
    parser.add_argument('--added-call', action='append', default=[], metavar='CALLER:TARGET')
    parser.add_argument('--reordered-calls', action='append', default=[],
                        metavar='CALLER:FIRST:SECOND',
                        help='require reversed first-call instruction layout; review branches for execution order')
    parser.add_argument('--new-string', action='append', default=[])
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    require(args.added_call or args.reordered_calls or args.new_string,
            'specify evidence of the intended change')
    require(bool(args.old_boot) == bool(args.new_boot), 'provide both boot images')
    old, new = args.old_kernel.read_bytes(), args.new_kernel.read_bytes()
    require(old != new, 'old and new kernels are identical')
    report = {'old_kernel': str(args.old_kernel), 'new_kernel': str(args.new_kernel),
              'kernel_bytes': [len(old), len(new)], 'kernels_differ': True, 'evidence': []}
    for marker in args.new_string:
        value = marker.encode()
        require(value not in old and value in new, f'expected a newly added string: {marker}')
        report['evidence'].append({'new_string': marker})
    if args.added_call or args.reordered_calls:
        tool = shutil.which('llvm-objdump')
        require(tool, 'llvm-objdump is required for call comparisons')
        for spec in args.added_call:
            caller, target = spec.split(':', 1)
            before = disassemble(tool, args.old_kernel, caller)
            after = disassemble(tool, args.new_kernel, caller)
            pattern = r'\b(?:bl|b)\s+[^\n]*<' + re.escape(target) + r'>'
            require(not re.search(pattern, before), f'old kernel already calls {target} from {caller}')
            require(re.search(pattern, after), f'new kernel does not call {target} from {caller}')
            report['evidence'].append({'added_call': spec,
                'new_instruction': next(line.strip() for line in after.splitlines() if re.search(pattern, line)),
                'disassembly_diff': ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                               fromfile='old', tofile='new'))})
        for spec in args.reordered_calls:
            caller, first, second = spec.split(':', 2)
            before = disassemble(tool, args.old_kernel, caller)
            after = disassemble(tool, args.new_kernel, caller)
            positions = []
            instructions = []
            for label, code in [('old', before), ('new', after)]:
                calls = []
                for target in (first, second):
                    pattern = r'\b(?:bl|b)\s+[^\n]*<' + re.escape(target) + r'>'
                    found = re.search(pattern, code)
                    require(found, f'{label} kernel: missing {caller} -> {target}')
                    calls.append(found.start())
                positions.append(calls)
                instructions.append([(code[:p].rsplit('\n', 1)[-1] + code[p:].splitlines()[0]).strip()
                                     for p in calls])
            require(positions[0][1] < positions[0][0],
                    f'old kernel does not call {second} before {first}')
            require(positions[1][0] < positions[1][1],
                    f'new kernel does not call {first} before {second}')
            report['evidence'].append({'reordered_calls': spec,
                'instruction_layout_only': True,
                'old_first_occurrences': instructions[0], 'new_first_occurrences': instructions[1],
                'new_instruction': f'{caller}: first {first} instruction now precedes {second}; review control flow',
                'disassembly_diff': ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                               fromfile='old', tofile='new'))})
    if args.new_boot:
        old_boot, old_payload = boot_payload(args.old_boot)
        new_boot, new_payload = boot_payload(args.new_boot)
        require(old_boot != new_boot and old_payload != new_payload, 'boot images or payloads are identical')
        report['boot_images_differ'] = True
        report['verified_payload_segments'] = [verify_payload(old_payload, old), verify_payload(new_payload, new)]
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print('Kernels differ; intended change confirmed.' +
          (' Both boot payloads match their respective kernels.' if args.new_boot else ''))
    for evidence in report['evidence']:
        print(evidence.get('new_instruction', evidence.get('new_string')))


if __name__ == '__main__':
    main()
