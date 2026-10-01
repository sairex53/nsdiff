project(
  'nsdiff',
  'c',
  version: '0.1.0',
  meson_version: '>=1.3',
  default_options: [
    'c_std=gnu17',
    'warning_level=3',
    'b_pie=true',
  ],
)

add_project_arguments(
  '-Wshadow',
  '-Wformat=2',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  '-Werror=implicit-function-declaration',
  language: 'c',
)

jansson_dep = dependency('jansson', version: '>=2.13')

libcap_dep = dependency(
  'libcap',
  required: true,
)

libmount_dep = dependency(
  'mount',
  required: true,
)

config_data = configuration_data()

config_data.set_quoted(
  'NSDIFF_VERSION',
  meson.project_version(),
)

configure_file(
  output: 'config.h',
  configuration: config_data,
)

inc = include_directories(
  'include',
)

config_inc = include_directories(
  '.',
)

cc = meson.get_compiler('c')
if get_option('hardening')
  add_project_arguments(cc.get_supported_arguments('-fstack-protector-strong'), language: 'c')
  if get_option('optimization') != '0'
    add_project_arguments('-D_FORTIFY_SOURCE=2', language: 'c')
  endif
  add_project_link_arguments(cc.get_supported_link_arguments('-Wl,-z,relro', '-Wl,-z,now', '-Wl,-z,noexecstack'), language: 'c')
endif

if get_option('fuzz')
  if cc.get_id() != 'clang'
    error('Fuzz targets require Clang and its libFuzzer runtime')
  endif
  add_project_arguments('-fsanitize=fuzzer-no-link,address,undefined', language: 'c')
  add_project_link_arguments('-fsanitize=address,undefined', language: 'c')
endif
subdir('src')
subdir('tests')
if get_option('fuzz')
  subdir('fuzz')
endif

man_config = configuration_data()
man_config.set('PROJECT_VERSION', meson.project_version())
man_page = configure_file(input: 'docs/nsdiff.1.in', output: 'nsdiff.1', configuration: man_config)
install_man(man_page)
install_data('completions/nsdiff.bash', rename: 'nsdiff', install_dir: get_option('datadir') / 'bash-completion/completions')
install_data('completions/_nsdiff', install_dir: get_option('datadir') / 'zsh/site-functions')
install_data('completions/nsdiff.fish', install_dir: get_option('datadir') / 'fish/vendor_completions.d')
