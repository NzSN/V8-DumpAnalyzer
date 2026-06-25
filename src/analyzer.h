#ifndef SRC_ANALYZER_H_
#define SRC_ANALYZER_H_

#include <string>

#include "src/types.h"

namespace dump_analyzer {

struct AnalyzerOptions {
  std::string dump_path;
  bool json_output = false;
};

class Analyzer {
 public:
  Analyzer();
  ~Analyzer();

  bool Run(const AnalyzerOptions& options, std::string* error_out);

 private:
  AnalysisResult result_;
};

}  // namespace dump_analyzer

#endif  // SRC_ANALYZER_H_
