#!/usr/bin/env python3
"""Generate the structural portable schema from explicitly serialized model members.
Runtime additionally enforces decoded byte lengths, numeric ranges and identities.
"""
import json
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
header = (root/'include/nsdiff/snapshot.h').read_text()
constants = dict((k, int(v)) for k, v in re.findall(r'#define (NSDIFF_\w+) (\d+)', header))

def size(s):
    return int(s) if s.isdigit() else constants[s]

def obj(properties):
    return {'type':'object', 'required':list(properties), 'properties':properties}

def byte_string(capacity):
    return {'description':f'Non-NUL bytes, maximum decoded length {capacity-1} bytes. UTF-8 byte length is checked by the importer.',
        'oneOf':[obj({'encoding':{'const':'utf-8'}, 'value':{'type':'string', 'maxLength':capacity-1, 'pattern':'^[^\\u0000]*$'}}),
                 obj({'encoding':{'const':'hex'}, 'value':{'type':'string', 'maxLength':2*(capacity-1), 'pattern':'^(?:(?!00)[0-9a-f]{2})*$'}})]}

unsigned = {'type':'string', 'pattern':'^(0|[1-9][0-9]*)$', 'maxLength':20,
            'description':'Unsigned decimal, <=18446744073709551615; importer also checks destination type range.'}
statuses = ['ok','permission-denied','not-supported','process-gone','io-error','parse-error','truncated']
enums = {'enum collect_status':statuses,
         'enum nsdiff_limit_kind':['nofile','nproc','stack','memlock','as','core','fsize'],
         'enum nsdiff_capset_kind':['inheritable','permitted','effective','bounding','ambient']}
defs = {}
for name, body in re.findall(r'struct (\w+)\s*\{(.*?)\};', header, re.S):
    properties = {}
    for declaration in body.split(';'):
        declaration = ' '.join(declaration.split())
        if not declaration: continue
        match = re.fullmatch(r'(.+?)\s+(\w+)\s*((?:\[\s*\w+\s*\]\s*)*)', declaration)
        if not match: raise ValueError(declaration)
        typ, field, arrays = match.groups()
        if field == 'pidfd': continue
        dims = [size(x) for x in re.findall(r'\[\s*(\w+)\s*\]', arrays)]
        if typ == 'char': value = byte_string(dims.pop())
        elif typ.startswith('struct '): value = {'$ref':'#/$defs/'+typ[7:]}
        elif typ in enums: value = {'enum':enums[typ]}
        elif typ == 'bool': value = {'type':'boolean'}
        elif typ in ('unsigned long long','unsigned long','dev_t','ino_t'): value = unsigned.copy()
        else: value = {'type':'integer', 'minimum':0, 'maximum':4294967295 if typ == 'unsigned int' else 2147483647}
        if field == 'pid': value['minimum'] = 1
        if field == 'starttime_ticks': value['pattern'] = '^[1-9][0-9]*$'
        if field == 'seccomp': value['maximum'] = 2
        if field == 'no_new_privs': value['maximum'] = 1
        if name == 'network_set_info' and field == 'count': value['maximum'] = 64
        if dims: value = {'type':'array', 'minItems':0 if name=='network_set_info' else dims[0], 'maxItems':dims[0], 'items':value}
        properties[field] = value
    defs[name] = obj(properties)
provenance = obj({'captured_sec':{'type':'string','pattern':'^(0|-?[1-9][0-9]*)$','maxLength':20,'description':'Signed 64-bit Unix seconds'},
    'captured_nsec':{'type':'integer','minimum':0,'maximum':999999999},'kernel':byte_string(128),'architecture':byte_string(64)})
schema = {'$schema':'https://json-schema.org/draft/2020-12/schema', 'title':'nsdiff portable snapshot v1',
    '$comment':'Importer additionally enforces exact decoded byte lengths, numeric ranges, fixed identities, unique logical set items, count equality and resource bounds. Unknown optional keys are permitted.',
    **obj({'document_type':{'const':'nsdiff-portable-snapshot'},'schema_version':{'const':1},
           'required_features':{'type':'array','maxItems':0},'producer':obj({'name':{'const':'nsdiff'},'version':{'type':'string','maxLength':31}}),
           'provenance':{'oneOf':[{'type':'null'},provenance]},'snapshot':{'$ref':'#/$defs/process_snapshot'}}), '$defs':defs}
output = json.dumps(schema, indent=2, ensure_ascii=True)+'\n'
path = root/'docs/schema/portable-snapshot-v1.schema.json'
if '--check' in sys.argv:
    if path.read_text() != output: raise SystemExit('Schema is stale; run scripts/generate-schema.py')
else:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(output)
