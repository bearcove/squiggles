# squiggles

A standalone LSP that continuously runs Rust tests and surfaces failures as editor diagnostics. Test failures appear as squiggly underlines, just like compiler errors.

<img width="1720" height="1520" alt="Squiggles working in Zed, showing a test failure" src="https://github.com/user-attachments/assets/a6c51f33-ee4c-40df-907f-598171943cc0" />

## What it does

- Watches for file saves and runs `cargo nextest run` automatically
- Publishes diagnostics on test function definitions (ERROR) and panic locations in backtraces (WARNING)
- Shows full panic output with backtrace on hover
- Displays pass/fail inlay hints next to `#[test]` attributes

## Installation

### Building from source

```bash
cargo xtask install
```

### Installing as a Zed dev extension

Clone this repo somewhere, then in Zed:

1. Open the command palette (`Cmd+Shift+P`)
2. Run `zed: install dev extension`
3. Select the `editors/zed-squiggles` directory

The extension will be loaded from source and reloaded when you make changes.

## Configuration

Squiggles is opt-in per workspace. Create `.config/squiggles/config.styx`:

```styx
@schema {id crate:squiggles-config@1, cli squiggles}

enabled true
```

### Options

```styx
@schema {id crate:squiggles-config@1, cli squiggles}

enabled true
debounce_ms 500
include (my_crate::*)
exclude (slow_tests::*)
```

- `enabled` - Must be `true` to activate
- `debounce_ms` - Delay after file save before running tests (default: 500)
- `include` - Test filter patterns (glob syntax, converted to nextest filters)
- `exclude` - Tests to skip

## Known issues

**Zed inlay hint conflict**: Zed replaces inlay hints when multiple LSPs emit them for the same file. You'll see either rust-analyzer's inlay hints or squiggles' pass/fail hints, but not both simultaneously.

## Requirements

- [cargo-nextest](https://nexte.st/) must be installed
- Rust project with tests

## How it works

1. LSP starts and watches for `.config/squiggles/config.styx`
2. On file save, waits for debounce period, then runs `cargo nextest run --message-format libtest-json-plus`
3. Parses test output, extracts panic locations and backtraces
4. Publishes diagnostics to the editor
5. Hover on a failing test to see the full panic message
