#include "src/heap-scanner.h"

#include <cstring>
#include <map>
#include <sstream>

#include "src/objects/instance-type.h"
#include "src/objects/tagged.h"

namespace dump_analyzer {

HeapScanner::HeapScanner() = default;
HeapScanner::~HeapScanner() = default;

const MemoryRegion* HeapScanner::FindV8HeapRegion(
    const std::vector<MemoryRegion>& regions) const {
  // Heuristic: V8 heap is typically the largest contiguous region.
  // A more precise approach would check against known V8 module ranges.
  const MemoryRegion* largest = nullptr;
  size_t max_size = 0;
  for (const auto& region : regions) {
    if (region.data.size() > max_size) {
      max_size = region.data.size();
      largest = &region;
    }
  }
  return largest;
}

HeapSummary HeapScanner::Scan(const std::vector<MemoryRegion>& regions,
                               const std::vector<MINIDUMP_MODULE>& modules,
                               std::vector<std::string>* warnings) {
  HeapSummary summary;
  summary.total_objects = 0;
  summary.total_size = 0;

  const MemoryRegion* heap_region = FindV8HeapRegion(regions);
  if (!heap_region) {
    warnings->push_back("No memory regions found — cannot scan V8 heap.");
    return summary;
  }

  ScanRange(heap_region->data.data(), heap_region->data.size(), &summary);
  return summary;
}

void HeapScanner::ScanRange(const uint8_t* start, size_t size,
                             HeapSummary* summary) {
  // Walk the memory region looking for potential tagged objects.
  // On V8 with pointer compression, heap objects are 4-byte aligned.
  // We look for Map words (tagged pointers to Map objects).
  //
  // A Map word is identified by:
  //   - Strong heap object tag (bit 0 = 1, bit 1 = 1)
  //   - Points within the same heap region
  //   - For known maps, we can identify the instance type

  constexpr size_t kPointerSize = 4;  // compressed pointer
  size_t offset = 0;

  while (offset + kPointerSize <= size) {
    uint32_t tagged;
    std::memcpy(&tagged, start + offset, sizeof(tagged));

    // Check if this looks like a strong tagged pointer
    // (lower bits: bit 0 = 1, bit 1 = 1 for strong heap object)
    if ((tagged & 0x3) == 0x3) {
      // Potentially a Map word at start of an object.
      // For now, record it. Full classification requires live V8.
      summary->total_objects++;
      summary->total_size += sizeof(uint32_t);

      // Attempt to skip based on estimated object size
      offset += sizeof(uint32_t);
    } else {
      offset += sizeof(uint32_t);
    }
  }
}

bool HeapScanner::TryClassifyObject(const uint8_t* heap_start,
                                     uint64_t address, size_t remaining,
                                     ObjectSummary* out) {
  // TODO: Full classification requires reading the Map object
  // and resolving its instance_type field. This requires live V8
  // symbol information for the specific build.
  return false;
}

}  // namespace dump_analyzer
