#!/usr/bin/env python3
"""Offline public-contract regressions, using frozen native ABI fixtures."""
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys
import tempfile

binary, fixture = map(lambda x: str(Path(x).resolve()), sys.argv[1:3])
checks = 0

def run(*args, rc=0, data=None, **kw):
    global checks
    p = subprocess.run([binary, *map(str, args)], input=data, capture_output=True, timeout=15, **kw)
    assert p.returncode == rc, (args, p.returncode, p.stderr.decode(errors='replace'))
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    checks += 1
    return p.stdout

def fnv(data):
    h = 14695981039346656037
    for b in data:
        h = ((h ^ b) * 1099511628211) & ((1 << 64)-1)
    return h

def container(payload, version):
    header = struct.pack('=16s4I2Q32s', b'NSDIFFSNAP', version, 1, 0x01020304, 0, len(payload), fnv(payload), b'0.0.24')
    ext = b''
    if version > 1:
        ext = struct.pack('=IIqiI128s64s', 216 if version == 2 else 256, 0, 1750000000, 123456789, 0, b'synthetic-kernel', b'synthetic-architecture')
        if version == 3:
            ext += struct.pack('=II32s', 1, 32, hashlib.sha256(payload).digest())
    return header+ext+payload

with tempfile.TemporaryDirectory(prefix='nsdiff-offline-') as tmp:
    root = Path(tmp)
    payload = subprocess.check_output([fixture])
    native = root/'v3.snap'
    portable = root/'portable.json'
    converted = root/'converted.snap'
    for version in (1, 2, 3):
        path = root/f'v{version}.snap'
        raw = container(payload, version)
        path.write_bytes(raw)
        run('--verify-snapshot', path)
        assert json.loads(run('--snapshot-info', path, '--json'))['format_version'] == version
        assert run('--snapshot-id', path).strip().decode() == 'nsdiff:sha256:'+hashlib.sha256(payload).hexdigest()
        run('--convert-snapshot', path, portable, '--snapshot-format', 'portable')
        assert run('--snapshots', path, portable, '--quiet') == b''
        run('--convert-snapshot', portable, converted, '--snapshot-format', 'native')
        run('--snapshots', path, converted, '--quiet')
        bad = root/'bad.snap'
        for changed in (raw[:3], raw[:79], raw[:-1], raw+b'x', raw[:-1]+bytes([raw[-1]^1]), raw[:16]+struct.pack('=I', 99)+raw[20:]):
            bad.write_bytes(changed)
            assert json.loads(run('--verify-snapshot', bad, '--json', rc=2))['valid'] is False
    run('--convert-snapshot', native, portable, '--snapshot-format', 'portable')
    original = json.loads(portable.read_bytes())
    assert original['snapshot']['limits']['entries'][0]['hard']['value'] == '18446744073709551615'
    assert original['snapshot']['starttime_ticks'] == '1234567890123456789'
    assert portable.stat().st_mode & 0o777 == 0o600
    assert converted.stat().st_mode & 0o777 == 0o600
    for report in ('--snapshot-info', '--snapshot-manifest'):
        result = json.loads(run(report, portable, '--json'))
        assert result['provenance']['captured_sec'] == '1750000000'
        assert result['provenance']['kernel'] == 'synthetic-kernel'
        assert result['stored_digest'] is None
    sid = run('--semantic-id', native)
    assert run('--semantic-id', portable) == sid
    # Fixed golden from a platform-independent fixture; CI runs this on x86_64/aarch64.
    assert sid.strip().decode() == 'nsdiff:semantic-sha256:745016f4aaf9f09a94274bbc3f13dfeaba8dae988871a9ca25b9f73b5e92f20c'
    mutated = root/'mutated.json'
    def put(o): mutated.write_text(json.dumps(o), encoding='utf-8'); return mutated
    reorder = copy.deepcopy(original)
    reorder['producer']['version'] = '2.0.0'
    reorder['provenance']['captured_sec'] = '0'
    reorder['provenance']['architecture']['value'] = 'foreign-architecture'
    reorder['snapshot']['network']['interfaces']['items'].reverse()
    for field in ('namespaces',): reorder['snapshot'][field].reverse()
    for section in ('limits', 'environment', 'mounts'): reorder['snapshot'][section]['entries'].reverse()
    reorder['snapshot']['cgroup']['files'].reverse()
    reorder['snapshot']['proc_status']['capabilities'].reverse()
    assert run('--semantic-id', put(reorder)) == sid
    reordered_json = json.dumps(original, sort_keys=True, separators=(',', ':')).encode()
    assert run('--semantic-id', '-', data=reordered_json) == sid
    # ABI padding and unused string tails cannot affect semantic identity.
    padded = bytearray(payload)
    # First namespace starts at offset 16 on frozen LP64 ABI; dev follows 4-byte padding.
    assert len(payload) == json.loads(run('--snapshot-schema', '--json'))['native_snapshot']['payload_bytes']
    padded[36:40] = b'PAD!'
    pad_file = root/'padding.snap'; pad_file.write_bytes(container(padded, 3))
    assert run('--semantic-id', pad_file) == sid
    assert run('--snapshot-id', pad_file) != run('--snapshot-id', native)
    # Semantic changes for every comparison domain, using the same diff engine.
    mutations = [
        lambda s: s['namespaces'][0].update(ino='777'),
        lambda s: s['proc_status']['uid'].__setitem__(1, '1234'),
        lambda s: s['limits']['entries'][0]['soft'].update(value='12'),
        lambda s: s['cgroup']['path'].update(value='/other'),
        lambda s: s['network']['interfaces']['items'][0].update(value='eth9'),
        lambda s: s['mounts']['entries'][0].update(read_only=True),
        lambda s: s['environment']['entries'][0]['value'].update(value='/elsewhere'),
        lambda s: s['proc_status'].update(no_new_privs=0),
    ]
    for change in mutations:
        o = copy.deepcopy(original); change(o['snapshot']); put(o)
        assert run('--snapshots', native, mutated, '--quiet', rc=1) == b''
        assert run('--semantic-id', mutated) != sid
        d = json.loads(run('--snapshots', native, mutated, '--json', rc=1))
        assert d['summary']['differences'] == 1
    for state in ({'present': False}, {'value': {'encoding':'utf-8','value':''}}, {'status':'permission-denied'}):
        o = copy.deepcopy(original); o['snapshot']['environment']['entries'][0].update(state)
        assert run('--semantic-id', put(o)) != sid
    # Exact bytes, including controls and invalid UTF-8, are retained through native.
    raw_bytes = bytes(range(1,256))
    o = copy.deepcopy(original)
    o['snapshot']['environment']['entries'][0]['value'] = {'encoding':'hex','value':raw_bytes.hex()}
    put(o); run('--convert-snapshot', mutated, converted, '--snapshot-format', 'native')
    roundtrip = root/'roundtrip.json'; run('--convert-snapshot', converted, roundtrip, '--snapshot-format', 'portable')
    assert json.loads(roundtrip.read_bytes())['snapshot']['environment']['entries'][0]['value'] == o['snapshot']['environment']['entries'][0]['value']
    exported = json.loads(run('--export-snapshot-json', converted))
    value = next(f for f in exported['fields'] if f['path']=='environment.PATH')['a']
    assert value.encode('latin1') == raw_bytes
    # Privacy and separate diagnostic/lossless document types.
    for args in [('--snapshots', native, native), ('--export-snapshot-json', native), ('--snapshot-manifest', native, '--json')]:
        assert b'TEST_SECRET' not in run(*args)
    bad = root/'bad.json'
    bad.write_bytes(run('--export-snapshot-json', native))
    run('--verify-snapshot', bad, rc=2)
    # Valid UTF-8 and equivalent hex yield the same identity.
    for value in ['"\\\n\t\x01\x7f', 'Привет🌑']:
        o = copy.deepcopy(original); field = o['snapshot']['environment']['entries'][0]
        field['value'] = {'encoding':'utf-8','value':value}; before = run('--semantic-id', put(o))
        field['value'] = {'encoding':'hex','value':value.encode().hex()}; assert run('--semantic-id', put(o)) == before
    malformed = [b'{', b'{}', b'[]', b'{"x":1,"x":2}', b'{"x":"\xff"}', b'{"x":"\\ud800"}', b'{"x":1e999}', b'['*40+b']'*40, reordered_json+b'x', b' '*((8<<20)+1)]
    changes = [lambda o:o.update(schema_version=2), lambda o:o.update(required_features=['new']),
        lambda o:o.pop('snapshot'), lambda o:o['snapshot'].update(pid=-1), lambda o:o['snapshot'].update(pid=True),
        lambda o:o['snapshot'].update(starttime_ticks='18446744073709551616'),
        lambda o:o['snapshot'].update(starttime_ticks='-1'), lambda o:o['snapshot'].update(starttime_ticks='01'),
        lambda o:o['snapshot']['network']['interfaces'].update(count=65),
        lambda o:o['snapshot']['network']['interfaces']['items'].__setitem__(1, o['snapshot']['network']['interfaces']['items'][0]),
        lambda o:o['snapshot']['namespaces'].__setitem__(1, o['snapshot']['namespaces'][0]),
        lambda o:o['snapshot']['environment']['entries'][25].update(redact_value=False),
        lambda o:o['snapshot']['environment']['entries'][0].update(status='bad'),
        lambda o:o['snapshot']['environment']['entries'][0].update(present=None),
        lambda o:o['snapshot']['environment']['entries'][0].update(value={'encoding':'hex','value':'00'}),
        lambda o:o['snapshot']['environment']['entries'][0].update(value={'encoding':'base64','value':'!!'}),
        lambda o:o['snapshot']['environment']['entries'][0].update(value={'encoding':'hex','value':'f'}),
        lambda o:o['snapshot']['environment']['entries'][0].update(value={'encoding':'hex','value':'zz'}),
        lambda o:o['snapshot']['environment']['entries'][0].update(value={'encoding':'utf-8','value':'x'*4096}),
        lambda o:o['snapshot']['proc_status'].update(seccomp=999),
    ]
    for change in changes:
        o = copy.deepcopy(original); change(o); malformed.append(json.dumps(o).encode())
    for content in malformed:
        bad.write_bytes(content)
        for command in ('--verify-snapshot','--snapshot-info','--snapshot-id','--snapshot-manifest','--snapshot-compat'):
            result = json.loads(run(command, bad, '--json', rc=2))
            assert result.get('valid') is False or result.get('compatible') is False
    # Unknown optional values are ignored, but still lexically bounded/validated.
    o = copy.deepcopy(original); o['future_optional'] = {'x':[1,2]}
    assert run('--semantic-id', put(o)) == sid
    # Native checksum-correct hostile fields must not reach renderers.
    for offset, value in [(0,b'\0'*4), (32,struct.pack('=I',999)), (16,b'x'*16), (8,b'\0'*8)]:
        evil = bytearray(payload); evil[offset:offset+len(value)] = value
        bad.write_bytes(container(evil,3)); run('--verify-snapshot',bad,rc=2)
    offsets = json.loads(subprocess.check_output([fixture, 'offsets']))
    duplicate = bytearray(payload)
    first = offsets['items']; width = offsets['item_size']
    duplicate[first+2*width:first+3*width] = duplicate[first:first+width]
    struct.pack_into('=I', duplicate, offsets['count'], 3)
    duplicate_file = root/'duplicate-native'; duplicate_file.write_bytes(container(duplicate,3))
    assert run('--semantic-id', duplicate_file) == sid
    assert run('--snapshot-id', duplicate_file) != run('--snapshot-id', native)
    run('--convert-snapshot', duplicate_file, converted, '--snapshot-format', 'portable')
    run('--snapshots', converted, native, '--quiet')
    for key, value in [('bool',b'\x02'), ('count',struct.pack('=I',0xffffffff)), ('status',struct.pack('=I',0xffffffff)), ('redact',b'\0')]:
        evil = bytearray(payload); offset=offsets[key]; evil[offset:offset+len(value)]=value
        bad.write_bytes(container(evil,3)); run('--verify-snapshot',bad,rc=2)
    for version in (1,2,3):
        raw=container(payload,version)
        for offset,value in [(20,struct.pack('=I',99)), (24,struct.pack('=I',0x04030201)), (32,struct.pack('=Q',0xffffffffffffffff)), (48,b'x'*32)]:
            evil=bytearray(raw);evil[offset:offset+len(value)]=value;bad.write_bytes(evil)
            run('--verify-snapshot',bad,rc=2)
        if version>1:
            evil=bytearray(raw);struct.pack_into('=I',evil,80,0xffffffff);bad.write_bytes(evil)
            run('--verify-snapshot',bad,rc=2)
    # Streams and unusual filenames, lossless path escaping in legacy byte-codepoint JSON.
    for command in ('--snapshot-info','--verify-snapshot','--snapshot-id','--snapshot-manifest','--snapshot-compat'):
        json.loads(run(command, '-', '--json', data=portable.read_bytes()))
    run('--snapshots', '-', portable, '--quiet', data=portable.read_bytes())
    run('--snapshots', '-', '-', '--quiet', rc=2)
    for name in ['space quote"\\\n', '-leading', 'Привет', os.fsdecode(b'bad\xff')]:
        path = root/name; path.write_bytes(portable.read_bytes())
        json.loads(run('--snapshot-info', path, '--json'))
    stream_native = run('--convert-snapshot', '-', '-', '--snapshot-format', 'native', data=portable.read_bytes())
    run('--verify-snapshot','-',data=stream_native)
    # Atomic replacement, symlink target preservation and parallel writers.
    target = root/'untouched'; target.write_bytes(b'keep')
    link = root/'link'; link.symlink_to(target)
    run('--convert-snapshot', native, link, '--snapshot-format','portable')
    assert not link.is_symlink() and target.read_bytes() == b'keep'
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: run('--convert-snapshot', native, portable, '--snapshot-format','portable'), range(32)))
    run('--verify-snapshot',portable)
    for path in (root/'missing'/'file',root): run('--convert-snapshot',native,path,'--snapshot-format','portable',rc=2)
    assert not list(root.glob('*.tmp.*'))
    def limit_size(): resource.setrlimit(resource.RLIMIT_FSIZE,(1024,1024))
    import signal
    def fault():
        limit_size(); signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
    prior = portable.read_bytes()
    run('--convert-snapshot',native,portable,'--snapshot-format','portable',rc=2,preexec_fn=fault)
    assert portable.read_bytes() == prior and not list(root.glob('*.tmp.*'))
    for args in [[],['42'],['1','2','3'],['--','-1','2'],['0','2'],['999999999999999999999','1'],['--bad'],['--capture'],['--snapshot-format','nope'],['--snapshot-format','portable','1','2'],['--convert-snapshot',native,portable],['--quiet','--json','1','2'],['--section','wat','1','2']]:
        run(*args,rc=2)
    # Quiet real differences, scoped comparisons and empty unavailable state remain rc 0.
    o = copy.deepcopy(original); o['snapshot']['network']['interfaces']['status'] = 'truncated'; put(o)
    assert run('--snapshots',native,mutated,'--quiet') == b''
    assert any(f['status_b']=='truncated' for f in json.loads(run('--snapshots',native,mutated,'--json'))['fields'])
print(f'PASS: {checks} offline command checks plus binary/schema assertions')
