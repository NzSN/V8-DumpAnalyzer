#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "minidump_reader.h"
#include "symbol_resolver.h"
#include "v8_scan.h"

const MD* g_md = nullptr;

void set_g_md(const MD* m) { g_md = m; }

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: dump_analyzer <dumpfile> [sympath]\n"
                    "  sympath = directory with .exe/.pdb files for symbol resolution\n");
    return 1;
  }

  MD m;
  if (!m.open(argv[1])) { fprintf(stderr, "Cannot open\n"); return 1; }

  printf("=== dump_analyzer ===\n");
  printf("Threads: %zu  Regions: %zu  Modules: %zu\n\n",
         m.th.size(), m.rs.size(), m.mods.size());

  Sym sym;
  if (argc > 2) sym.init(argv[2], m);

  auto oom = m.annot.find("v8-oom-stack");
  auto js  = m.annot.find("javascript_stack_trace");
  if (oom != m.annot.end()) printf("=== V8 OOM Stack ===\n%s\n\n", oom->second.c_str());
  if (js  != m.annot.end()) printf("=== JS Stack ===\n%s\n\n", js->second.c_str());

  auto ai = m.annot.find("v8_isolate_address");
  auto ro = m.annot.find("v8_ro_space_firstpage_address");
  uint64_t iso = 0, ro_addr = 0;
  if (ai != m.annot.end()) iso = strtoull(ai->second.c_str(), nullptr, 0);
  if (ro != m.annot.end()) ro_addr = strtoull(ro->second.c_str(), nullptr, 0);

  if (!iso) {
    rewind(m.f);
    char buf[65536];
    while (fread(buf, 1, sizeof(buf), m.f) == sizeof(buf)) {
      for (size_t i = 0; i < sizeof(buf) - 32; i++) {
        if (memcmp(buf + i, "v8_isolate_address = 0x", 22) == 0)
          iso = strtoull(buf + i + 22, nullptr, 0);
        if (memcmp(buf + i, "v8_ro_space_firstpage_address = 0x", 34) == 0)
          ro_addr = strtoull(buf + i + 34, nullptr, 0);
      }
    }
    if (!iso && !ro_addr) { rewind(m.f); fseek(m.f, 0, SEEK_END); }
  }
  if (ro_addr) g_cage = ro_addr & 0xFFFFFFFF00000000ULL;

  printf("=== Annotations ===\n");
  printf("  v8_isolate_address = 0x%llx\n  V8 cage base        = 0x%llx\n\n",
         (unsigned long long)iso, (unsigned long long)g_cage);

  sym.walk(m);

  uint64_t stk_start = 0, stk_end = 0;
  for (auto& t : m.th) {
    if (m.hc && t.tid == m.crash_tid) {
      stk_start = t.st.ad; stk_end = t.st.ad + t.st.sz;
    }
  }
  uint64_t cef = iso ? v8_scan_cef(m, iso, stk_start, stk_end) : 0;
  if (cef) {
    printf("=== V8 JS Frames (from c_entry_fp) ===\n");
    uint64_t fp = cef;
    for (int d = 0; fp && d < 256; d++) {
      uint64_t ra, nfp;
      if (!m.rdm(fp + 8, 8, &ra)) break;
      if (!m.rdm(fp, 8, &nfp)) break;
      if (nfp == 0 || nfp == fp) break;
      std::string n = v8_js_name(m, fp);
      printf("  #%02d  | 0x%013llx | %s\n", d, (unsigned long long)ra,
             n.empty() ? "(native)" : n.c_str());
      fp = nfp;
    }
    printf("\n");
  } else if (iso) {
    printf("  (c_entry_fp not found - JS frames unavailable)\n\n");
  }

  return 0;
}
