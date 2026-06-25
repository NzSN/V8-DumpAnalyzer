#ifndef SRC_OUTPUT_FORMATTER_H_
#define SRC_OUTPUT_FORMATTER_H_

#include <string>

#include "src/types.h"

namespace dump_analyzer {

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
