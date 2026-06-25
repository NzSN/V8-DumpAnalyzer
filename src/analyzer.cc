#include "src/analyzer.h"

#include "src/minidump-reader.h"
#include "src/heap-scanner.h"
#include "src/output-formatter.h"

#include <cstdio>

namespace dump_analyzer {

Analyzer::Analyzer() = default;
Analyzer::~Analyzer() = default;

bool Analyzer::Run(const AnalyzerOptions& options, std::string* error_out) {
  result_ = AnalysisResult{};
  result_.minidump_path = options.dump_path;

  // Step 1: Read the minidump file.
  MinidumpReader reader;
  if (!reader.Open(options.dump_path, error_out)) {
    return false;
  }

  result_.regions = reader.memory_regions();

  // Step 2: Scan for V8 heap.
  HeapScanner scanner;
  result_.heap = scanner.Scan(result_.regions, reader.modules(),
                               &result_.warnings);

  // Step 3: Format and print output.
  OutputFormatter formatter(options.json_output);
  std::string output = formatter.Format(result_);
  std::printf("%s", output.c_str());

  return true;
}

}  // namespace dump_analyzer
