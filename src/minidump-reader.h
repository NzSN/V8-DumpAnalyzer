#ifndef SRC_MINIDUMP_READER_H_
#define SRC_MINIDUMP_READER_H_

#include <cstddef>
#include <string>
#include <vector>

#include "src/types.h"

namespace dump_analyzer {

class MinidumpReader {
 public:
  MinidumpReader();
  ~MinidumpReader();

  // Opens and parses a minidump file. Returns false on error with message in
  // |error_out|.
  bool Open(const std::string& path, std::string* error_out);

  // Accessors for parsed data.
  const std::vector<MemoryRegion>& memory_regions() const {
    return memory_regions_;
  }

  const std::vector<MINIDUMP_THREAD>& threads() const { return threads_; }

  const std::vector<MINIDUMP_MODULE>& modules() const { return modules_; }

  // Read raw bytes from a memory region at the given address.
  bool ReadMemory(uint64_t address, size_t size,
                  std::vector<uint8_t>* out) const;

 private:
  bool ParseHeader();
  bool ParseStreams(const std::vector<uint8_t>& data);
  bool ParseMemoryList(const std::vector<uint8_t>& data, uint32_t rva);
  bool ParseThreadList(const std::vector<uint8_t>& data, uint32_t rva);
  bool ParseModuleList(const std::vector<uint8_t>& data, uint32_t rva);

  std::vector<uint8_t> file_data_;
  std::vector<MemoryRegion> memory_regions_;
  std::vector<MINIDUMP_THREAD> threads_;
  std::vector<MINIDUMP_MODULE> modules_;
  std::string error_;
};

}  // namespace dump_analyzer

#endif  // SRC_MINIDUMP_READER_H_
