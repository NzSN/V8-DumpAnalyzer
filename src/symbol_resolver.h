#pragma once
#include <windows.h>
#include <dbghelp.h>
#include <dia2.h>
#include <map>
#include <string>

#include "minidump_reader.h"

BOOL CALLBACK read_mem(HANDLE, DWORD64 addr, PVOID buf, DWORD sz, LPDWORD read);

struct Sym {
  HANDLE proc;
  bool ok = false;

  bool init(const char* sympath, const MD& m);
  std::string resolve(uint64_t addr);
  void walk(const MD& m);
  ~Sym();

private:
  IDiaSession* get_dia(uint64_t mod_base);
  std::map<uint64_t, IDiaSession*> dia_sessions;
  std::map<uint64_t, IDiaDataSource*> dia_sources;
};
