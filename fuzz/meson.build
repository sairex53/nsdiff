names = ['native', 'portable', 'bytes', 'json']
foreach i : range(4)
  executable('fuzz-' + names[i], 'parse.c',
    include_directories: [inc, config_inc], dependencies: [jansson_dep, libcap_dep, libmount_dep],
    link_with: nsdiff_core, c_args: ['-DFUZZ_MODE=' + i.to_string()],
    link_args: ['-fsanitize=fuzzer,address,undefined'], install: false)
endforeach
