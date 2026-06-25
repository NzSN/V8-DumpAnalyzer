#include "src/output-formatter.h"

#include <sstream>

namespace dump_analyzer {

OutputFormatter::OutputFormatter(bool json_output)
    : json_output_(json_output) {}

OutputFormatter::~OutputFormatter() = default;

std::string OutputFormatter::Format(const AnalysisResult& result) const {
  if (json_output_) {
    return FormatJson(result);
  }
  return FormatText(result);
}

std::string OutputFormatter::FormatText(const AnalysisResult& result) const {
  std::ostringstream oss;

  oss << "Dump Analyzer Report\n";
  oss << "====================\n";
  oss << "File: " << result.minidump_path << "\n\n";

  oss << "Memory Regions: " << result.regions.size() << "\n";
  for (size_t i = 0; i < result.regions.size(); i++) {
    oss << "  [" << i << "] 0x" << std::hex << result.regions[i].start_address
        << std::dec << "  size=" << result.regions[i].data.size() << "\n";
  }
  oss << "\n";

  const auto& heap = result.heap;
  oss << "Heap Summary\n";
  oss << "  Total objects: " << heap.total_objects << "\n";
  oss << "  Total size:    " << heap.total_size << " bytes\n";

  if (!heap.by_type.empty()) {
    oss << "\nBy Type:\n";
    for (const auto& type : heap.by_type) {
      oss << "  " << type.type_name << ": count=" << type.count
          << "  size=" << type.total_size << "\n";
    }
  }

  if (!result.warnings.empty()) {
    oss << "\nWarnings:\n";
    for (const auto& w : result.warnings) {
      oss << "  " << w << "\n";
    }
  }

  return oss.str();
}

std::string OutputFormatter::FormatJson(const AnalysisResult& result) const {
  std::ostringstream oss;
  oss << "{\n";
  oss << "  \"file\": " << detail::JSONEscape(result.minidump_path) << ",\n";
  oss << "  \"regions\": [\n";
  for (size_t i = 0; i < result.regions.size(); i++) {
    if (i > 0) oss << ",\n";
    oss << "    {\"address\": " << result.regions[i].start_address
        << ", \"size\": " << result.regions[i].data.size() << "}";
  }
  oss << "\n  ],\n";
  oss << "  \"heap\": {\n";
  oss << "    \"total_objects\": " << result.heap.total_objects << ",\n";
  oss << "    \"total_size\": " << result.heap.total_size << "\n";
  oss << "  },\n";
  oss << "  \"warnings\": [\n";
  for (size_t i = 0; i < result.warnings.size(); i++) {
    if (i > 0) oss << ",\n";
    oss << "    " << detail::JSONEscape(result.warnings[i]);
  }
  oss << "\n  ]\n";
  oss << "}\n";
  return oss.str();
}

}  // namespace dump_analyzer
