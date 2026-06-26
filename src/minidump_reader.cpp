#include "minidump_reader.h"
#include <cstring>

bool MD::open(const char* path) {
  f = fopen(path, "rb");
  if (!f) return false;
  MDH h;
  fread(&h, sizeof(h), 1, f);
  if (h.sig != 0x504D444D) return false;
  for (uint32_t i = 0; i < h.ns; i++) {
    MDD d;
    fseek(f, h.sdr + i * 12, SEEK_SET);
    fread(&d, sizeof(d), 1, f);
    if (d.ty == 0x43500001 && d.sz > 36) {
      uint32_t sr, ss;
      rd(d.rva + 36, 4, &sr);
      rd(d.rva + 40, 4, &ss);
      if (sr && ss) {
        std::vector<char> buf(ss);
        rd(sr, ss, buf.data());
        std::string blob(buf.data(), ss);
        size_t pos = 0;
        while (pos < blob.size()) {
          size_t end = blob.find('\0', pos);
          if (end == std::string::npos) break;
          std::string entry(&blob[pos], end - pos);
          auto eq = entry.find('=');
          if (eq != std::string::npos)
            annot[entry.substr(0, eq)] = entry.substr(eq + 1);
          pos = end + 1;
        }
      }
    }
    if (d.ty == 5) {
      uint32_t n; rd(d.rva, 4, &n);
      for (uint32_t j = 0; j < n; j++) {
        Reg r;
        rd(d.rva + 4 + j*16, 8, &r.ad);
        rd(d.rva + 4 + j*16+8, 4, &r.sz);
        rd(d.rva + 4 + j*16+12, 4, &r.rva);
        rs.push_back(r);
      }
    }
    if (d.ty == 3) {
      uint32_t n; rd(d.rva, 4, &n);
      th.resize(n);
      for (uint32_t j = 0; j < n; j++)
        rd(d.rva + 4 + j*sizeof(MDT), sizeof(MDT), &th[j]);
    }
    if (d.ty == 4) {
      uint32_t n; rd(d.rva, 4, &n);
      mods.resize(n);
      for (uint32_t j = 0; j < n; j++) {
        Mod mod;
        rd(d.rva + 4 + j*108 + 0, 8, &mod.base);
        rd(d.rva + 4 + j*108 + 8, 4, &mod.sz);
        rd(d.rva + 4 + j*108 + 20, 4, &mod.namerva);
        rd(d.rva + 4 + j*108 + 76, 4, &mod.cv_sz);
        rd(d.rva + 4 + j*108 + 80, 4, &mod.cv_rva);
        mods[j] = mod;
      }
    }
    if (d.ty == 6) {
      uint32_t cs, cr; uint64_t ad;
      rd(d.rva, 4, &crash_tid);
      rd(d.rva + 24, 8, &ad);
      rd(d.rva + 160, 4, &cs);
      rd(d.rva + 164, 4, &cr);
      rd(cr, sizeof(MDCX), &cx);
      hc = true;
    }
  }
  return true;
}

bool MD::rd(uint32_t rva, size_t sz, void* buf) const {
  return fseek(f, rva, SEEK_SET) == 0 && fread(buf, 1, sz, f) == sz;
}

bool MD::rdm(uint64_t addr, size_t sz, void* buf) const {
  for (auto& r : rs)
    if (addr >= r.ad && addr < r.ad + r.sz)
      return rd(r.rva + uint32_t(addr - r.ad), sz, buf);
  for (auto& t : th)
    if (addr >= t.st.ad && addr < t.st.ad + t.st.sz)
      return rd(t.st.rva + uint32_t(addr - t.st.ad), sz, buf);
  return false;
}
