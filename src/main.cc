#include <cstdio>
#include <cstring>
#include <string>

#include "src/analyzer.h"

void PrintUsage() {
  std::printf(
      "V8 Dump Analyzer\n"
      "Usage: dump-analyzer [options] <minidump.dmp>\n"
      "\n"
      "Options:\n"
      "  --json       Output JSON instead of text\n"
      "  --help       Show this help\n");
}

int main(int argc, char* argv[]) {
  dump_analyzer::AnalyzerOptions options;

  // Parse arguments.
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--json") == 0) {
      options.json_output = true;
    } else if (std::strcmp(argv[i], "--help") == 0) {
      PrintUsage();
      return 0;
    } else if (argv[i][0] == '-') {
      std::fprintf(stderr, "Unknown option: %s\n", argv[i]);
      PrintUsage();
      return 1;
    } else {
      options.dump_path = argv[i];
    }
  }

  if (options.dump_path.empty()) {
    std::fprintf(stderr, "Error: no minidump file specified.\n");
    PrintUsage();
    return 1;
  }

  dump_analyzer::Analyzer analyzer;
  std::string error;
  if (!analyzer.Run(options, &error)) {
    std::fprintf(stderr, "Error: %s\n", error.c_str());
    return 1;
  }

  return 0;
}
