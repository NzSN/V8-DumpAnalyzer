#include "src/minidump-reader.h"

#include <cstring>
#include <sstream>

namespace dump_analyzer {

MinidumpReader::MinidumpReader() = default;
MinidumpReader::~MinidumpReader() = default;

bool MinidumpReader::Open(const std::string& path, std::string* error_out) {
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    std::ostringstream oss;
    oss << "Cannot open file: " << path;
    *error_out = oss.str();
    return false;
  }

  fseek(fp, 0, SEEK_END);
  size_t size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  file_data_.resize(size);
  if (fread(file_data_.data(), 1, size, fp) != size) {
    fclose(fp);
    *error_out = "Failed to read file";
    return false;
  }
  fclose(fp);

  if (!ParseHeader()) {
    *error_out = error_;
    return false;
  }
  if (!ParseStreams(file_data_)) {
    *error_out = error_;
    return false;
  }
  return true;
}

bool MinidumpReader::ParseHeader() {
  if (file_data_.size() < sizeof(MINIDUMP_HEADER)) {
    error_ = "File too small for minidump header";
    return false;
  }
  MINIDUMP_HEADER header;
  std::memcpy(&header, file_data_.data(), sizeof(header));

  if (header.signature != kMinidumpSignature) {
    error_ = "Invalid minidump signature";
    return false;
  }
  return true;
}

bool MinidumpReader::ParseStreams(const std::vector<uint8_t>& data) {
  if (data.size() < sizeof(MINIDUMP_HEADER)) {
    error_ = "File too small";
    return false;
  }

  MINIDUMP_HEADER header;
  std::memcpy(&header, data.data(), sizeof(header));

  uint32_t dir_offset = header.stream_directory_rva;
  for (uint32_t i = 0; i < header.number_of_streams; i++) {
    uint32_t off = dir_offset + i * sizeof(MINIDUMP_DIRECTORY);
    if (off + sizeof(MINIDUMP_DIRECTORY) > data.size()) break;

    MINIDUMP_DIRECTORY dir;
    std::memcpy(&dir, data.data() + off, sizeof(dir));

    switch (dir.stream_type) {
      case kMemoryListStream:
        if (!ParseMemoryList(data, dir.location.rva)) return false;
        break;
      case kThreadListStream:
        if (!ParseThreadList(data, dir.location.rva)) return false;
        break;
      case kModuleListStream:
        if (!ParseModuleList(data, dir.location.rva)) return false;
        break;
    }
  }
  return true;
}

bool MinidumpReader::ParseMemoryList(const std::vector<uint8_t>& data,
                                     uint32_t rva) {
  if (rva + sizeof(uint32_t) > data.size()) {
    error_ = "Invalid memory list RVA";
    return false;
  }
  uint32_t count;
  std::memcpy(&count, data.data() + rva, sizeof(count));

  uint32_t offset = rva + sizeof(uint32_t);
  for (uint32_t i = 0; i < count; i++) {
    if (offset + sizeof(MINIDUMP_MEMORY_DESCRIPTOR) > data.size()) break;

    MINIDUMP_MEMORY_DESCRIPTOR desc;
    std::memcpy(&desc, data.data() + offset, sizeof(desc));
    offset += sizeof(MINIDUMP_MEMORY_DESCRIPTOR);

    MemoryRegion region;
    region.start_address = desc.start_of_memory_range;
    uint32_t data_off = desc.memory.rva;
    uint32_t data_size = desc.memory.data_size;

    if (data_off + data_size <= data.size()) {
      region.data.assign(data.data() + data_off,
                         data.data() + data_off + data_size);
    } else if (data_off < data.size()) {
      region.data.assign(data.data() + data_off, data.end());
    }
    memory_regions_.push_back(std::move(region));
  }
  return true;
}

bool MinidumpReader::ParseThreadList(const std::vector<uint8_t>& data,
                                     uint32_t rva) {
  if (rva + sizeof(uint32_t) > data.size()) {
    error_ = "Invalid thread list RVA";
    return false;
  }
  uint32_t count;
  std::memcpy(&count, data.data() + rva, sizeof(count));

  uint32_t offset = rva + sizeof(uint32_t);
  for (uint32_t i = 0; i < count; i++) {
    if (offset + sizeof(MINIDUMP_THREAD) > data.size()) break;
    MINIDUMP_THREAD thread;
    std::memcpy(&thread, data.data() + offset, sizeof(thread));
    offset += sizeof(MINIDUMP_THREAD);
    threads_.push_back(thread);
  }
  return true;
}

bool MinidumpReader::ParseModuleList(const std::vector<uint8_t>& data,
                                     uint32_t rva) {
  if (rva + sizeof(uint32_t) > data.size()) {
    error_ = "Invalid module list RVA";
    return false;
  }
  uint32_t count;
  std::memcpy(&count, data.data() + rva, sizeof(count));

  uint32_t offset = rva + sizeof(uint32_t);
  for (uint32_t i = 0; i < count; i++) {
    if (offset + sizeof(MINIDUMP_MODULE) > data.size()) break;
    MINIDUMP_MODULE module;
    std::memcpy(&module, data.data() + offset, sizeof(module));
    offset += sizeof(MINIDUMP_MODULE);
    modules_.push_back(module);
  }
  return true;
}

bool MinidumpReader::ReadMemory(uint64_t address, size_t size,
                                std::vector<uint8_t>* out) const {
  for (const auto& region : memory_regions_) {
    uint64_t start = region.start_address;
    uint64_t end = start + region.data.size();
    if (address >= start && address + size <= end) {
      size_t offset = address - start;
      out->assign(region.data.begin() + offset,
                  region.data.begin() + offset + size);
      return true;
    }
  }
  return false;
}

}  // namespace dump_analyzer
