python = find_program('python3')
live_runner = files('run_live.py')
legacy_tests = [
  'cli.sh',
  'integration.sh',
  'json.sh',
  'network.sh',
  'scope.sh',
  'snapshot.sh',
  'snapshot_atomic.sh',
  'snapshot_compat.sh',
  'snapshot_digest.sh',
  'snapshot_export.sh',
  'snapshot_identity.sh',
  'snapshot_info.sh',
  'snapshot_manifest.sh',
  'snapshot_metadata_json.sh',
  'snapshot_provenance.sh',
  'snapshot_schema.sh',
  'snapshot_stream.sh',
]
foreach script : legacy_tests
  test(script.split('.')[0].replace('_', '-'), python,
    args: [live_runner, files(script), nsdiff_exe], suite: 'live', timeout: 120)
endforeach
fixture_exe = executable('native-fixture', 'fixture.c', install: false)
sha_exe = executable('test-sha256', 'sha256.c', '../src/sha256.c', include_directories: inc)
test('sha256-kat', sha_exe, suite: 'unit')
unit_exe = executable('test-unit', 'unit.c', '../src/json_bytes.c', '../src/proc_read.c',
    include_directories: inc, dependencies: jansson_dep)
test('bytes-json-proc-unit', unit_exe, suite: 'unit')
test('portable-native-regression', python, args: [files('portable.py'), nsdiff_exe, fixture_exe],
    suite: ['snapshot', 'security', 'cli'], timeout: 180)

test('portable-schema', python, args: files('schema.py'), suite: 'snapshot')
