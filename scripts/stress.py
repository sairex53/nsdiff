#!/usr/bin/env python3
import concurrent.futures, json, os, resource, subprocess, sys, tempfile, time
from pathlib import Path
binary=str(Path(sys.argv[1]).resolve()); count=int(sys.argv[2]); started=time.monotonic()
o=json.loads((Path(__file__).resolve().parents[1]/'tests/fixtures/portable-v1.json').read_bytes())
s=o['snapshot'];s['cgroup']['path']['value']='/'+'a'*4094
for e in s['environment']['entries']: e['present']=True;e['value']['value']='v'*4095
s['environment']['total_entries']=33
for net in s['network'].values():
    net['count']=64;net['items']=[{'encoding':'utf-8','value':f'entry{i:03}-'+'x'*180} for i in range(64)]
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp); source=root/'source';source.write_text(json.dumps(o))
    def work(i):
        dest=root/f'{i}.snap'
        subprocess.run([binary,'--convert-snapshot',str(source),str(dest),'--snapshot-format','native'],check=True,stdout=subprocess.DEVNULL)
        subprocess.run([binary,'--snapshots',str(source),str(dest),'--quiet'],check=True)
        dest.unlink()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(work,range(count)))
    assert not list(root.glob('*.tmp.*'))
    # Input close to the 8 MiB limit, without relaxing lexical resource limits.
    near=b' '*(8*1024*1024-source.stat().st_size)+source.read_bytes()
    subprocess.run([binary,'--verify-snapshot','-'],input=near,check=True,stdout=subprocess.DEVNULL)
    if int(Path('/proc/self/stat').read_bytes().split(b' ',1)[0])==os.getpid():
        for _ in range(min(count,100)):
            p=subprocess.Popen(['true'])
            result=subprocess.run([binary,'--capture',str(root/'race'),str(p.pid)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            assert result.returncode in (0,2);p.wait()
    else: print('NOT RUN: rapid live capture; procfs/PID namespaces differ')
print(f'PASS: {count} parallel conversion/load cycles; bounded arrays, long values, near-limit document; {time.monotonic()-started:.2f}s')
print(f'child max RSS reported by getrusage: {resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss} KiB')
