# V8 Dump Analyzer — Design Spec

## Purpose

A C++ tool that analyzes V8 heap memory from minidump (crash dump) files. Parses the minidump format, locates V8 heap regions, and produces structured summaries of heap state — object counts, types, sizes, and memory layout.

## Project Structure

```
~/Repos/V8-DumpAnalyzer/
├── .gn                  # GN build root — references //build/config/BUILDCONFIG.gn
├── BUILD.gn             # Main build target (dump_analyzer executable)
├── DEPS                 # gclient DEPS — pulls V8 + buildtools + Chromium build
├── overrides/
│   └── build.gni        # Build overrides for standalone V8 embedding
├── src/
│   ├── main.cc          # CLI entry point, argument parsing
│   ├── analyzer.h       # Core analysis orchestrator
│   ├── analyzer.cc
│   ├── minidump-reader.h    # Minidump format reader (streaming, not mmap)
│   ├── minidump-reader.cc
│   ├── heap-scanner.h       # V8 heap traversal using V8 internal types
│   ├── heap-scanner.cc
│   ├── output-formatter.h   # Structured output (text/JSON)
│   └── output-formatter.cc
└── docs/
    └── superpowers/specs/   # Design documents
```

## Build System

- **Build tool:** GN + Ninja (via Chromium's `//build` config)
- **V8 dependency:** Pulled via DEPS into `v8/` subdirectory
- **Target definition:** `v8_executable("dump_analyzer")` in project's `BUILD.gn`
- **Config:** Uses `internal_config_base` (manually) plus `v8_libbase`, `v8_libplatform`
- **Link deps:** `:v8` + `:v8_libbase` + `:v8_libplatform`

The `.gn` file uses `secondary_source = "//v8/"` to resolve V8's internal targets.

## Component Architecture

```text
main.cc
  └─ Analyzer::Run(options)
       ├─ MinidumpReader::Open(path)
       │    ├─ Parse header + directories
       │    ├─ Locate MemoryList, ThreadList, ModuleList
       │    └─ Return memory regions + thread context
       ├─ HeapScanner::Scan(&regions)
       │    ├─ Identify V8 heap pages via known map addresses
       │    └─ Walk objects, classify by instance type
       └─ OutputFormatter::Format(results)
            └─ Print summary (text or JSON)
```

### MinidumpReader

Parses the Microsoft Minidump format (MINIDUMP_HEADER, directories, streams). No V8 dependency — standalone parser. Key streams:
- **MemoryListStream** — all captured memory regions
- **ThreadListStream** — thread contexts (stack pointers)
- **ModuleListStream** — loaded modules to locate V8 .text

### HeapScanner

Uses V8 internal types (`src/objects/`, `src/heap/`) to interpret heap memory:
- Locates heap pages via known page boundaries
- Uses Map words to determine object types
- Walks object ranges to count instances and measure sizes
- References `v8heapconst`-style constants for known maps/roots

### OutputFormatter

Two output modes:
- **Text** — human-readable summary (tree of object types with counts/sizes)
- **JSON** — machine-readable for scripting

## CLI Interface

```
dump-analyzer [options] <minidump.dmp>

Options:
  --json              Output JSON instead of text
  --v8-symbols PATH   Path to V8 symbols / debug info
  --verbose           Detailed per-object output
```

## Error Handling

- Invalid/corrupt minidump → descriptive error + non-zero exit
- No V8 heap found → message + exit code 1
- Partial memory capture → best-effort with warnings

## Non-Goals

- No REPL or interactive mode (use grokdump.py for that)
- No web server mode
- No disassembly
- No live debugging or attaching to processes
