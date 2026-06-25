#ifndef SRC_TYPES_H_
#define SRC_TYPES_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace dump_analyzer {

// ── Minidump format structures ──────────────────────────────────────────────

struct MINIDUMP_HEADER {
  uint32_t signature;
  uint32_t version;
  uint32_t number_of_streams;
  uint32_t stream_directory_rva;
  uint32_t check_sum;
  uint32_t reserved;
  uint64_t time_date_stamp;
  uint64_t flags;
};

struct MINIDUMP_LOCATION_DESCRIPTOR {
  uint32_t data_size;
  uint32_t rva;
};

struct MINIDUMP_DIRECTORY {
  uint32_t stream_type;
  MINIDUMP_LOCATION_DESCRIPTOR location;
};

struct MINIDUMP_MEMORY_DESCRIPTOR {
  uint64_t start_of_memory_range;
  MINIDUMP_LOCATION_DESCRIPTOR memory;
};

struct MINIDUMP_MEMORY_LIST {
  uint32_t number_of_memory_ranges;
  // Followed by MINIDUMP_MEMORY_DESCRIPTOR[n]
};

struct MINIDUMP_THREAD {
  uint32_t thread_id;
  uint32_t suspend_count;
  uint32_t priority_class;
  uint32_t priority;
  uint64_t teb;
  MINIDUMP_MEMORY_DESCRIPTOR stack;
  MINIDUMP_LOCATION_DESCRIPTOR thread_context;
};

struct MINIDUMP_THREAD_LIST {
  uint32_t number_of_threads;
  // Followed by MINIDUMP_THREAD[n]
};

struct MINIDUMP_MODULE {
  uint64_t base_of_image;
  uint32_t size_of_image;
  uint32_t checksum;
  uint32_t time_date_stamp;
  uint32_t module_name_rva;
  // ... (simplified, fields omitted for brevity)
};

struct MINIDUMP_MODULE_LIST {
  uint32_t number_of_modules;
  // Followed by MINIDUMP_MODULE[n]
};

// ── Memory region ───────────────────────────────────────────────────────────

struct MemoryRegion {
  uint64_t start_address;
  std::vector<uint8_t> data;
};

// ── Analysis result types ───────────────────────────────────────────────────

struct ObjectSummary {
  std::string type_name;   // Instance type name (e.g., "JS_FUNCTION")
  int instance_type;       // Numeric instance type
  size_t count;
  size_t total_size;
};

struct HeapSummary {
  size_t total_objects;
  size_t total_size;
  std::vector<ObjectSummary> by_type;
  std::vector<ObjectSummary> by_space;
};

struct AnalysisResult {
  std::string minidump_path;
  std::vector<MemoryRegion> regions;
  HeapSummary heap;
  std::vector<std::string> warnings;
};

// ── Stream type constants ───────────────────────────────────────────────────

enum MinidumpStreamType : uint32_t {
  kUnusedStream = 0,
  kReservedStream0 = 1,
  kReservedStream1 = 2,
  kThreadListStream = 3,
  kModuleListStream = 4,
  kMemoryListStream = 5,
  kExceptionStream = 6,
  kSystemInfoStream = 7,
  kMiscInfoStream = 8,
};

constexpr uint32_t kMinidumpSignature = 0x504d444d;  // "MDMP"

}  // namespace dump_analyzer

#endif  // SRC_TYPES_H_
