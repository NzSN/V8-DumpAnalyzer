#include "v8_scan.h"

uint64_t g_cage = 0x23000000000ULL;

std::string v8_read_str(const MD& m, uint64_t addr) {
  if (addr < g_cage) return "";
  uint32_t len;
  if (!m.rdm(addr + 12, 4, &len) || len < 1 || len > 256) return "";
  char buf[257] = {};
  m.rdm(addr + 16, len, buf);
  return buf;
}

bool v8_read_ptr(const MD& m, uint64_t addr, uint64_t* out) {
  uint32_t compressed;
  if (!m.rdm(addr, 4, &compressed) || !compressed) return false;
  *out = g_cage + compressed;
  return true;
}

std::string v8_js_name(const MD& m, uint64_t fp) {
  uint64_t jsfunc, shared;
  if (!v8_read_ptr(m, fp - 16, &jsfunc)) return "";
  if (!v8_read_ptr(m, jsfunc + 0x10, &shared)) return "";
  return v8_read_str(m, shared + 16);
}

uint64_t v8_scan_cef(const MD& m, uint64_t iso, uint64_t stk_start, uint64_t stk_end) {
  if (!iso || !stk_start) return 0;
  for (uint32_t off = 0; off < 4096; off += 8) {
    uint64_t v;
    if (!m.rdm(iso + off, 8, &v)) continue;
    if (v < stk_start || v >= stk_end) continue;
    uint64_t ra;
    if (m.rdm(v + 8, 8, &ra) && ra > 0x7ff000000000ULL) return v;
  }
  return 0;
}
