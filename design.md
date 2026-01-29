# Sentinel - Continuous Cargo Test LSP

A standalone LSP that continuously runs cargo tests and surfaces runtime failures as editor diagnostics.

## Philosophy

Treat test failures like compiler errors:
- Tests run continuously on save
- Failures appear as squiggly underlines in the editor
- Hover shows full panic/failure output
- No terminal hunting required

## Scope

This is NOT:
- A test runner UI
- A replacement for cargo
- A general-purpose test framework

This IS:
- A single-purpose LSP for test diagnostics
- Treats runtime failures as first-class diagnostics

## Core Behavior

1. Watch for file saves in the workspace
2. Run `cargo nextest run` (excluding doctests - too slow)
3. Parse failures and extract source locations from panics/backtraces
4. Publish diagnostics to the editor

## Dependencies

### Serde zone (unavoidable - tower-lsp requirement)
- `tower-lsp` - LSP framework, brings serde
- `serde` / `serde_json` - only for LSP message types

### Facet zone (everything else)
- `facet` - core reflection
- `facet-json` - parsing nextest JSON output
- `figue` - CLI argument parsing (minimal use)

### Other
- `tokio` - async runtime (tower-lsp is built on it)
- `notify` - filesystem watching for save detection

## Nextest Integration

Using `cargo nextest run --message-format libtest-json-plus` for machine-readable output.

The `libtest-json-plus` variant includes an extra `nextest` field with additional metadata.

### Output Format

Nextest outputs newline-delimited JSON (JSONL). Requires env var `NEXTEST_EXPERIMENTAL_LIBTEST_JSON=1`.

**Message types:**

1. **Suite started**
```json
{"type":"suite","event":"started","test_count":6,"nextest":{"crate":"sample-crate","test_binary":"sample_crate","kind":"lib"}}
```

2. **Test started**
```json
{"type":"test","event":"started","name":"sample-crate::sample_crate$tests::test_passing"}
```

3. **Test passed**
```json
{"type":"test","event":"ok","name":"sample-crate::sample_crate$tests::test_passing","exec_time":0.006818375}
```

4. **Test failed** (with backtrace in `stdout` field)
```json
{"type":"test","event":"failed","name":"sample-crate::sample_crate$tests::test_panic_in_nested_call","exec_time":0.022801875,"stdout":"...panic message and backtrace..."}
```

5. **Suite finished**
```json
{"type":"suite","event":"failed","passed":1,"failed":5,"ignored":0,"measured":0,"filtered_out":0,"exec_time":0.120977625,"nextest":{"crate":"sample-crate","test_binary":"sample_crate","kind":"lib"}}
```

**Test name format:** `{crate}::{binary}${module}::{test_name}` (note the `$` separator)

**Panic location parsing:** The `stdout` field contains panic output like:
```
thread 'tests::test_panic_in_nested_call' (41538916) panicked at src/lib.rs:10:5:
something went wrong in inner function
stack backtrace:
   0: __rustc::rust_begin_unwind
             at /rustc/.../library/std/src/panicking.rs:689:5
   ...
   2: sample_crate::inner_panic
             at ./src/lib.rs:10:5
   3: sample_crate::helper_that_panics
             at ./src/lib.rs:6:5
```

Key patterns to extract:
- Primary panic location: `panicked at {file}:{line}:{col}:`
- Backtrace frames: `at {path}:{line}:{col}` (filter for `./` prefix = user code)

## Diagnostics Strategy

For each test failure:
1. Parse panic message and backtrace
2. Extract file:line references from user code (filter out std/deps)
3. Emit diagnostic on the panic location
4. Emit related diagnostics on backtrace frames in user code
5. Hover shows full panic output + context

## Editor Features

- **Diagnostics**: Squiggly underlines on failure locations
- **Hover**: Full panic/failure message with backtrace
- **Inlay hints** (future): Test status near test functions

## Open Questions

- Debounce strategy for rapid saves?
- How to handle workspace vs single-crate projects?
- Filter strategy for backtrace frames (only user code, or include deps?)
