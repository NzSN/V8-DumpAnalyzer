# V8 Dump Analyzer

Analyzes V8 heap memory from minidump (crash dump) files.

## Build

Requires `gclient`, `gn`, and `ninja`.

```bash
cd ~/Repos/V8-DumpAnalyzer
gclient sync
gn gen out/Release --args='is_debug=false'
ninja -C out/Release dump_analyzer
```

## Usage

```text
dump-analyzer [options] <minidump.dmp>

Options:
  --json       Output JSON instead of text
  --help       Show this help
```

Example:

```bash
./out/Release/dump_analyzer crash.dmp
./out/Release/dump_analyzer --json crash.dmp
```

## Architecture

```
main.cc
  └─ Analyzer::Run(options)
       ├─ MinidumpReader::Open(path)     — parse minidump format
       ├─ HeapScanner::Scan(regions)     — walk V8 heap, count objects
       └─ OutputFormatter::Format(...)    — text or JSON output
```

Components link against V8 (`:v8 + :v8_libbase + :v8_libplatform`) for access to internal heap types.
