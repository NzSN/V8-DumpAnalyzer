#include "symbol_resolver.h"
#include <comdef.h>
#include <cstdio>
#include <cstdlib>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

extern const MD* g_md;

BOOL CALLBACK read_mem(HANDLE, DWORD64 addr, PVOID buf, DWORD sz, LPDWORD read) {
  if (!g_md || !g_md->rdm(addr, sz, buf)) return FALSE;
  *read = sz; return TRUE;
}

bool Sym::init(const char* path, const MD& m) {
  proc = GetCurrentProcess();
  CoInitialize(NULL);
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_LOAD_ANYTHING);
  if (!SymInitialize(proc, NULL, FALSE)) return false;
  if (path) SymSetSearchPath(proc, path);

  for (auto& mod : m.mods) {
    wchar_t wname[MAX_PATH]; wname[0] = 0;
    m.rd(mod.namerva + 4, sizeof(wname) - 2, wname);
    char aname[MAX_PATH] = {};
    wcstombs(aname, wname, MAX_PATH - 1);
    const char* fname = strrchr(aname, '\\');
    fname = fname ? fname + 1 : aname;

    std::string found = aname;
    if (GetFileAttributesA(found.c_str()) == INVALID_FILE_ATTRIBUTES && path && *fname) {
      std::string spath = path;
      size_t start = 0;
      while (start < spath.size()) {
        size_t end = spath.find(';', start);
        std::string dir = spath.substr(start, end == std::string::npos ? spath.size() : end);
        if (!dir.empty()) {
          std::string full = dir + "\\" + fname;
          if (GetFileAttributesA(full.c_str()) != INVALID_FILE_ATTRIBUTES) {
            found = full; break;
          }
        }
        if (end == std::string::npos) break;
        start = end + 1;
      }
    }
    if (mod.cv_sz > 0 && mod.cv_rva > 0 && GetFileAttributesA(found.c_str()) != INVALID_FILE_ATTRIBUTES) {
      std::vector<char> cv(mod.cv_sz);
      if (m.rd(mod.cv_rva, mod.cv_sz, cv.data())) {
        MODLOAD_DATA mld = { sizeof(MODLOAD_DATA), 0xD2F4AC7A, cv.data(), mod.cv_sz, 0 };
        SymLoadModuleEx(proc, NULL, found.c_str(), fname, mod.base, mod.sz, &mld, 0);
      }
    } else {
      SymLoadModuleEx(proc, NULL, found.c_str(), NULL, mod.base, mod.sz, NULL, 0);
    }
  }

  // Open DIA sessions via DllGetClassObject (msdia140.dll may not be COM-registered)
  for (auto& mod : m.mods) {
    IMAGEHLP_MODULE64 mi = { sizeof(IMAGEHLP_MODULE64) };
    if (!SymGetModuleInfo64(proc, mod.base, &mi) || !mi.LoadedPdbName[0])
      continue;
    wchar_t wpdb[MAX_PATH] = {};
    mbstowcs(wpdb, mi.LoadedPdbName, MAX_PATH);
    IDiaDataSource* src = NULL;
    HMODULE hDia = LoadLibraryW(L"msdia140.dll");
    if (hDia) {
      auto DllGC = (decltype(&DllGetClassObject))GetProcAddress(hDia, "DllGetClassObject");
      if (DllGC) {
        IClassFactory* cf = NULL;
        if (SUCCEEDED(DllGC(CLSID_DiaSource, IID_IClassFactory, (void**)&cf))) {
          if (SUCCEEDED(cf->CreateInstance(NULL, IID_IDiaDataSource, (void**)&src))) {
            if (SUCCEEDED(src->loadDataFromPdb(wpdb))) {
              IDiaSession* sess = NULL;
              if (SUCCEEDED(src->openSession(&sess))) {
                dia_sessions[mod.base] = sess;
                dia_sources[mod.base] = src;
                cf->Release();
                continue;
              }
            }
          }
          cf->Release();
        }
      }
    }
    if (src) src->Release();
  }

  ok = true;
  return true;
}

std::string Sym::resolve(uint64_t addr) {
  if (!ok) return {};
  uint64_t mod_base = SymGetModuleBase64(proc, addr);
  auto it = dia_sessions.find(mod_base);

  // DIA scope-level resolution (finds public+private symbols like CDB)
  if (it != dia_sessions.end()) {
    IDiaSymbol* sym = NULL;
    LONG disp = 0;
    ULONGLONG rva = addr - mod_base;
    if (SUCCEEDED(it->second->findSymbolByRVAEx((DWORD)rva, SymTagNull, &sym, &disp)) && sym) {
      // Walk lexical parent chain if innermost symbol has no name
      IDiaSymbol* named = sym; sym = NULL;
      while (named) {
        BSTR nm = NULL; named->get_name(&nm);
        DWORD len = SysStringLen(nm); SysFreeString(nm);
        if (len > 0) break; // found named symbol
        IDiaSymbol* parent = NULL;
        if (FAILED(named->get_lexicalParent(&parent)) || !parent) break;
        DWORD prva = 0; parent->get_relativeVirtualAddress(&prva);
        if (prva) disp = (LONG)(rva - prva);
        named->Release(); named = parent;
      }
      // Also try findSymbolByRVAEx with SymTagFunction for function name
      if (!named) {
        IDiaSymbol* fnsym = NULL; LONG fnd = 0;
        if (SUCCEEDED(it->second->findSymbolByRVAEx((DWORD)rva, SymTagFunction, &fnsym, &fnd)) && fnsym) {
          named = fnsym;
          disp = fnd;
        }
      }
      if (named) {
        BSTR wname;
        if (SUCCEEDED(named->get_name(&wname))) {
          char aname[1024]; wcstombs(aname, wname, sizeof(aname)); SysFreeString(wname);
          named->Release();
          std::string r = aname;
          if (disp > 0) { char tmp[64]; snprintf(tmp, sizeof(tmp), "+0x%lx", disp); r += tmp; }
          DWORD ldisp; IMAGEHLP_LINE64 line; memset(&line, 0, sizeof(line)); line.SizeOfStruct = sizeof(line);
          if (SymGetLineFromAddr64(proc, addr, &ldisp, &line)) {
            const char* fn = strrchr(line.FileName, '\\'); fn = fn ? fn + 1 : line.FileName;
            char tmp[256]; snprintf(tmp, sizeof(tmp), " [%s:%lu]", fn, line.LineNumber); r += tmp;
          }
          return " " + r;
        }
        named->Release();
      }
    }
  }

  // SymFromAddr fallback
  alignas(SYMBOL_INFO) char buf[sizeof(SYMBOL_INFO) + 256];
  SYMBOL_INFO* si = (SYMBOL_INFO*)buf;
  si->SizeOfStruct = sizeof(SYMBOL_INFO); si->MaxNameLen = 255;
  DWORD64 disp = 0; std::string r;
  if (SymFromAddr(proc, addr, &disp, si)) {
    r += si->Name;
    if (disp) { char tmp[64]; snprintf(tmp, sizeof(tmp), "+0x%llx", (unsigned long long)disp); r += tmp; }
  }
  DWORD ldisp; IMAGEHLP_LINE64 line; memset(&line, 0, sizeof(line)); line.SizeOfStruct = sizeof(line);
  if (SymGetLineFromAddr64(proc, addr, &ldisp, &line)) {
    const char* fn = strrchr(line.FileName, '\\'); fn = fn ? fn + 1 : line.FileName;
    char tmp[256]; snprintf(tmp, sizeof(tmp), " [%s:%lu]", fn, line.LineNumber); r += tmp;
  }
  return r.empty() ? "" : " " + r;
}

void Sym::walk(const MD& m) {
  if (!ok || !m.hc) return;
  CONTEXT ctx = {};
  memcpy(&ctx, &m.cx, sizeof(m.cx));
  ctx.ContextFlags = CONTEXT_FULL;
  STACKFRAME64 sf = {};
  sf.AddrPC.Offset = ctx.Rip;
  sf.AddrPC.Mode = AddrModeFlat;
  sf.AddrStack.Offset = ctx.Rsp;
  sf.AddrStack.Mode = AddrModeFlat;
  sf.AddrFrame.Offset = ctx.Rbp;
  sf.AddrFrame.Mode = AddrModeFlat;
  printf("=== Native Stack ===\n");
  extern void set_g_md(const MD*);
  set_g_md(&m);
  for (int d = 0; d < 256; d++) {
    if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, proc, NULL, &sf, &ctx,
                     read_mem, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
      break;
    std::string s = resolve(sf.AddrPC.Offset);
    if (d == 0)
      printf("  #cr  | 0x%013llx | <crash>%s\n", (unsigned long long)sf.AddrPC.Offset, s.c_str());
    else
      printf("  #%02d  | 0x%013llx |%s\n", d, (unsigned long long)sf.AddrPC.Offset, s.c_str());
  }
  printf("\n");
  set_g_md(nullptr);
}

Sym::~Sym() {
  for (auto& p : dia_sessions) p.second->Release();
  for (auto& p : dia_sources) p.second->Release();
  CoUninitialize();
  if (ok) SymCleanup(proc);
}
