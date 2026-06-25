#ifndef SRC_HEAP_SCANNER_H_
#define SRC_HEAP_SCANNER_H_

#include <string>
#include <vector>

#include "src/types.h"

namespace dump_analyzer {

class HeapScanner {
 public:
  HeapScanner();
  ~HeapScanner();

  // Scan memory regions for V8 heap objects. Returns a summary of findings.
  HeapSummary Scan(const std::vector<MemoryRegion>& regions,
                   const std::vector<MINIDUMP_MODULE>& modules,
                   std::vector<std::string>* warnings);

 private:
  // Find V8 heap memory within captured regions. Returns the memory region
  // likely containing V8 heap, or nullptr.
  const MemoryRegion* FindV8HeapRegion(
      const std::vector<MemoryRegion>& regions) const;

  // Scan a memory range word-by-word, identifying potential objects.
  void ScanRange(const uint8_t* start, size_t size,
                 HeapSummary* summary);

  // Attempt to classify a potential object at |address|.
  bool TryClassifyObject(const uint8_t* heap_start, uint64_t address,
                         size_t remaining, ObjectSummary* out);
};

}  // namespace dump_analyzer

#endif  // SRC_HEAP_SCANNER_H_
