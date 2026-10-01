# nsdiff 0.1.0 — final report

Подготовлена версия 0.1.0 на базе исходного commit `b7e5f5b` (0.0.24).
Реализованы portable snapshots, обратный импорт, conversion и semantic identity.
Исходные CLI modes, sections, exit codes и native payload identity сохранены.
Это подготовленный исходный репозиторий; release tag и push не выполнялись.
Перед тегом необходимы live-проверки на обычном Linux и решение автора о лицензии.

## Изменения и архитектура

- Snapshot I/O разделён на ограниченный входной поток, native container, portable
  JSON, typed model, byte encoding, atomic writer и SHA-256. Один diff engine
  обслуживает оба формата. Main содержит CLI orchestration, а не второй serializer.
- Portable schema v1 хранит все retained semantic fields, collection status,
  presence, redaction flags, provenance и точные Linux bytes. Jansson >=2.13 —
  новая системная зависимость; собственного JSON grammar parser нет.
- Широкие числа представлены decimal strings. Byte objects различают UTF-8 и
  lowercase hex. Embedded NUL отклоняется; nonzero bytes 1..255 round-trip проверен.
  Описаны field schema, fixed identities, ranges, sizes и evolution rules.
- Import восстанавливает logical array order и проверяет missing/duplicate items.
  Network sets сортируются; portable duplicates отклоняются, legacy native
  duplicates нормализуются в памяти без изменения native raw ID.
- `--snapshot-format native|portable`, `--convert-snapshot IN OUT` и `--semantic-id`
  работают с файлами и `-`. Portable info/manifest показывают provenance и явно
  отличают отсутствие stored digest от успешной schema validation.
- Native v1/v2/v3 layout не изменён. Добавлен только status value `truncated` без
  изменения структуры/номеров существующих enum. Новые readers строже отвергают
  malformed payloads. Старый reader не понимает новый статус при его наличии.
- `nsdiff:sha256:` по-прежнему хеширует raw native payload, включая ABI padding.
  Новый `nsdiff:semantic-sha256:` использует canonical typed JSON, исключает
  PID/starttime, provenance, producer и layout. Identity сильнее выбранных diff
  fields: rc 0 не гарантирует одинаковый semantic ID. Алгоритм документирован.
- Legacy diagnostic JSON schema 1 сохраняет byte-codepoint escaping и integer
  types. Общий escaping закрывает невалидный UTF-8 в metadata/path output.
  Redacted diagnostic export не принимается как lossless snapshot.

## Hardening и исправления аудита

Native loader раньше полагался на container hashes и не проверял все bool/count/
enum/string representations перед rendering. Теперь model validation выполняется
до их использования. Input ограничен 8 MiB, JSON nesting — 32, lexical string —
32768 bytes, lexical nodes/commas — 32768. Unknown required features отклоняются;
unknown optional keys разрешены с теми же resource bounds.

Общий writer использует случайное имя, O_EXCL/O_NOFOLLOW, mode 0600, полный write,
fsync файла, renameat и fsync того же открытого parent directory. Проверены
symlink replacement, concurrent writers, ошибки пути и short write через
RLIMIT_FSIZE. Обычные ошибки убирают temporary file; fatal signal может оставить
private temporary file — это документировано, без небезопасного signal handler.

Добавлены pidfd liveness check, starttime before/after, bounded proc line reader,
поддержка newline в stat comm, явный truncation status, network deduplication,
редакция proxy на import, общий stdout error check и обработка SIGPIPE.
PIE, stack protector, RELRO/NOW, noexecstack и optimized FORTIFY включены.

Удалены случайные пустые tracked файлы из корня. Man page получает версию из Meson;
добавлены README, formats/security docs, changelog, completions, CI и validation
scripts. Release script проверяет уже чистый commit, ничего не stage/commit/tag/push
и отвергает skipped tests. Это исключает прежний риск частично созданного release.

## Фактически выполненные проверки

Среда: Ubuntu 24.04.3 LTS x86_64, GCC 13.3.0, Clang 18.1.3, Meson 1.3.2,
Valgrind 3.22.0, cppcheck 2.13.0, Jansson 2.14. Проверки: 2026-09-28 UTC.

| Проверка | Результат |
|---|---|
| GCC/Clang strict sanitizer compile (`-Dwerror=true`) | PASS, без compiler warnings |
| GCC/Clang ASan + UBSan | PASS для доступных offline tests, findings нет; LSan отдельно ниже |
| GCC debug и release tests | 4 OK, 0 FAIL, 17 SKIP |
| GCC/Clang sanitizer tests | в каждой сборке 4 OK, 0 FAIL, 17 SKIP |
| Meson registration | все 21 test entry points зарегистрированы |
| Offline CLI/native/portable regression | 332 command checks плюс binary/schema assertions |
| Native v1/v2/v3 | PASS, независимый frozen 0.0.24 header и containers с корректными hashes |
| Native → portable → native, mixed diff | PASS, equivalent diff rc 0; changes по всем 8 domains дают rc 1 |
| Raw/semantic IDs | PASS, SHA known-answer tests, fixed semantic golden, order/padding/provenance invariance |
| Malformed input, bounds, bytes, JSON, streams, privacy | PASS в offline regression/unit tests |
| Atomic/private writes | PASS: 0600, symlink target preservation, 32 writers, RLIMIT_FSIZE rollback |
| Structural JSON Schema | PASS: schema check, shared fixture и invalid examples |
| Valgrind | 5 scenarios, каждый 0 errors, 0 bytes/blocks at exit |
| Static analysis | PASS: cppcheck, Clang analyzer, curated clang-tidy checks; unresolved diagnostics нет |
| Fuzz | 4 targets, по 10 секунд requested / 11 фактически, crashes/findings нет |
| Stress | 1000 parallel conversion/load cycles, long fields, max network arrays, input 8 MiB: PASS |
| ELF hardening | PASS: PIE, RELRO/NOW, nonexec stack, stack protector, FORTIFY |
| `meson install` | PASS в отдельный writable prefix |
| `DESTDIR` install | PASS; binary, man, Bash/Zsh/Fish completions установлены |
| `meson dist` | PASS: fresh archive build/test/install; 4 OK и те же 17 environment skips |
| Source hygiene | `git diff --check` PASS; финальный Git tree clean; build/temp файлов в ZIP нет |

Fuzz iterations в финальном запуске: native 1,365; portable 25,055; byte encoding
1,607,133; JSON parser 36,140. Corpus включает valid portable fixture, native
v1/v2/v3, corrupt/truncated input. Native fuzz чаще останавливается на hash gate;
checksum-correct malformed semantic payloads отдельно проверяются regression suite.
Clang-tidy использует core/unix/deadcode и конкретные bugprone checks; blanket
Annex K warnings о каждом snprintf/memcpy не выдаются за полезный security audit.

Stress занял 3.12 s; child high-water RSS из getrusage — 31,032 KiB (включает
особенности subprocess/fork, не является изолированным профилем C heap).
Performance sanity, 100 invocations с startup: native info 3.678 ms, portable info
2.075 ms, mixed diff 3.913 ms. Это smoke measurement, не performance guarantee.
Исходный 0.0.24 был собран; на synthetic native fixture шесть output modes
сопоставлены с прежним renderer (за исключением tool_version), без регрессии.

## NOT RUN и ограничения

| Проверка | Причина / следующая проверка |
|---|---|
| 17 исходных live tests | `/proc` относится к другому PID namespace; исходный baseline тоже не мог выполнять live collection. Запустить весь Meson suite по VERIFY_ON_LINUX.md |
| LeakSanitizer | не может открыть `/proc/<namespace-pid>/task`; финальные ASan runs использовали `detect_leaks=0`. На обычном Linux запускать с `detect_leaks=1` |
| Rapid-exit live stress и live benchmark | то же несоответствие `/proc`; scripts автоматически выполняют их в нормальной среде |
| Fedora/aarch64 и физический cross-architecture exchange | доступна только Ubuntu x86_64; CI подготовлен, но remote CI не запускался |
| Полный release gate / tag | специально не пройден до live/LSan checks; `scripts/release.sh` должен завершиться без skips |
| hidepid/LSM/seccomp/pidfd fallback matrix, forced PID reuse | нужны управляемые отдельные Linux environments; automatic live smoke не покрывает всю матрицу |
| Exhaustive fault injection | проверены short write/invalid parent/symlink/concurrency; ENOSPC, rename/fsync failure и crash-at-every-instruction не инъецировались |

Portable design не сериализует C layout и содержит общий semantic golden для
x86_64/aarch64, но это не заменяет фактический ARM run. При импорте в более узкие
native types out-of-range values отвергаются, а не обрезаются.

Collection остаётся неатомарным относительно exec/configuration changes. При
недоступном pidfd starttime fallback имеет остаточный риск very fast PID reuse.
libmount allocation зависит от размера реального mount table. Cgroup lookup
предполагает conventional v2 mount. Часть legacy human descriptive strings
сохраняет terminal bytes; для untrusted data следует использовать escaped JSON.

Snapshots и semantic IDs могут раскрывать private values; redaction относится к
proxy diagnostic output, а не lossless storage. SHA-256 не даёт authenticity.
Все fixtures синтетические. Лицензии в исходном проекте не было; LICENSE не
выдуман. Решение автора необходимо до публичного open-source redistribution.
