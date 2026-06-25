#ifndef SRC_OUTPUT_FORMATTER_H_
#define SRC_OUTPUT_FORMATTER_H_

#include <string>

#include "src/types.h"

namespace dump_analyzer {

namespace detail {
inline std::string JSONEscape(const std::string& s) {
  std::string out;
  out.push_back('"');
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c);
    }
  }
  out.push_back('"');
  return out;
}
}  // namespace detail

class OutputFormatter {
 public:
  explicit OutputFormatter(bool json_output);
  ~OutputFormatter();

  std::string Format(const AnalysisResult& result) const;

 private:
  std::string FormatText(const AnalysisResult& result) const;
  std::string FormatJson(const AnalysisResult& result) const;

  bool json_output_;
};

}  // namespace dump_analyzer

#endif  // SRC_OUTPUT_FORMATTER_H_
