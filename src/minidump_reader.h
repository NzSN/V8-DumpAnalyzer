#pragma once
#include <cstdio>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#pragma pack(push, 1)
struct MDH { uint32_t sig, ver, ns, sdr; };
struct MDD { uint32_t ty, sz, rva; };
struct MDR { uint64_t ad; uint32_t sz, rva; };
struct MDT { uint32_t tid, sc, pc, pr; uint64_t teb; MDR st; uint32_t cs, cr; };
struct MDCX { uint64_t ph[6]; uint32_t cf, mx; uint16_t cs,ds,es,fs,gs,ss;
  uint32_t ef; uint64_t dr0,dr1,dr2,dr3,dr6,dr7;
  uint64_t rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi;
  uint64_t r8,r9,r10,r11,r12,r13,r14,r15,rip; };
#pragma pack(pop)
struct Reg { uint64_t ad; size_t sz; uint32_t rva; };
struct Mod { uint64_t base; uint32_t sz, namerva, cv_sz, cv_rva; };

struct MD {
  FILE* f;
  std::vector<MDT> th;
  std::vector<Reg> rs;
  MDCX cx;
  bool hc = false;
  uint32_t crash_tid = 0;
  std::vector<Mod> mods;
  std::map<std::string, std::string> annot;

  bool open(const char* path);
  bool rd(uint32_t rva, size_t sz, void* buf) const;
  bool rdm(uint64_t addr, size_t sz, void* buf) const;
};
