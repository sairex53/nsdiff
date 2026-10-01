# Dependencies and licensing

No third-party source is vendored and the build does not download dependencies.

- Jansson >=2.13, MIT/Expat, https://github.com/akheron/jansson : strict JSON
  parsing/tree/writing. Shared system dependency found by pkg-config/Meson.
  Upstream license: https://github.com/akheron/jansson/blob/master/LICENSE .
- libcap, retained system dependency; consult its distribution copyright and
  upstream https://git.kernel.org/pub/scm/libs/libcap/libcap.git/ .
- libmount (util-linux), retained system dependency; consult its LGPL library
  copyright and upstream https://github.com/util-linux/util-linux .

Python, Bash, Meson/Ninja and optional analysis/fuzzing/Valgrind tools are development
dependencies. There is no runtime network dependency.

The supplied nsdiff repository had no LICENSE file. None has been invented.
The author must choose and document the project's license and confirm compatibility
with dependencies before public distribution. Jansson's permissive license does
not establish the license of nsdiff itself.
