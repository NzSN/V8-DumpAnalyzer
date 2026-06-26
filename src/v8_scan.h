#pragma once
#include <cstdint>
#include <string>
#include "minidump_reader.h"

extern uint64_t g_cage;

std::string v8_read_str(const MD& m, uint64_t addr);
bool v8_read_ptr(const MD& m, uint64_t addr, uint64_t* out);
std::string v8_js_name(const MD& m, uint64_t fp);
uint64_t v8_scan_cef(const MD& m, uint64_t iso, uint64_t stk_start, uint64_t stk_end);
