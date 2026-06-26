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
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_ANYTHING);
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
    SymLoadModuleEx(proc, NULL, found.c_str(), NULL, mod.base, mod.sz, NULL, 0);
  }

  // Remove eager DIA loading — load on demand in resolve()
  ok = true;
  return true;
}

// Lazy-load DIA session for a module
IDiaSession* Sym::get_dia(uint64_t mod_base) {
  if (!ok) return NULL;
  auto it = dia_sessions.find(mod_base);
  if (it != dia_sessions.end()) return it->second;
  // Load on demand
  IMAGEHLP_MODULE64 mi = { sizeof(IMAGEHLP_MODULE64) };
  if (!SymGetModuleInfo64(proc, mod_base, &mi) || !mi.LoadedPdbName[0])
    return NULL;
  // Load PDB path is known from CV record even with deferred loads
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
              dia_sessions[mod_base] = sess;
              dia_sources[mod_base] = src;
              cf->Release();
              return sess;
            }
          }
        }
        cf->Release();
      }
    }
  }
  if (src) src->Release();
  return NULL;
}

std::string Sym::resolve(uint64_t addr) {
  if (!ok) return {};
  uint64_t mod_base = SymGetModuleBase64(proc, addr);

  // DIA scope-level resolution
  IDiaSession* session = get_dia(mod_base);
  if (session) {
    IDiaSymbol* sym = NULL;
    LONG disp = 0;
    ULONGLONG rva = addr - mod_base;
    if (SUCCEEDED(session->findSymbolByRVAEx((DWORD)rva, SymTagNull, &sym, &disp)) && sym) {
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
        if (SUCCEEDED(session->findSymbolByRVAEx((DWORD)rva, SymTagFunction, &fnsym, &fnd)) && fnsym) {
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

  // Step 1: walk stack to collect addresses
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
  extern void set_g_md(const MD*);
  set_g_md(&m);
  std::vector<uint64_t> addrs;
  for (int d = 0; d < 256; d++) {
    if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, proc, NULL, &sf, &ctx,
                     read_mem, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
      break;
    addrs.push_back(sf.AddrPC.Offset);
  }
  set_g_md(nullptr);

  // Step 2: locate electron.exe image path
  std::string exe_path;
  for (auto& mod : m.mods) {
    wchar_t wname[MAX_PATH] = {};
    m.rd(mod.namerva + 4, sizeof(wname) - 2, wname);
    char aname[MAX_PATH] = {};
    wcstombs(aname, wname, sizeof(aname));
    if (!strstr(aname, "electron.exe")) continue;
    IMAGEHLP_MODULE64 mi = { sizeof(IMAGEHLP_MODULE64) };
    if (SymGetModuleInfo64(proc, mod.base, &mi)) exe_path = mi.LoadedImageName;
    break;
  }

  std::map<uint64_t, std::string> sym_map, src_map;
  if (!exe_path.empty()) {
    // Copy PDB alongside EXE (required by llvm-symbolizer)
    char pdb_dst[MAX_PATH];
    snprintf(pdb_dst, sizeof(pdb_dst), "%s.pdb", exe_path.c_str());
    for (auto& mod : m.mods) {
      wchar_t wname[MAX_PATH] = {};
      m.rd(mod.namerva + 4, sizeof(wname) - 2, wname);
      char aname[MAX_PATH] = {}; wcstombs(aname, wname, sizeof(aname));
      if (!strstr(aname, "electron.exe")) continue;
      IMAGEHLP_MODULE64 mi = { sizeof(IMAGEHLP_MODULE64) };
      if (SymGetModuleInfo64(proc, mod.base, &mi) && mi.LoadedPdbName[0]) {
        CopyFileA(mi.LoadedPdbName, pdb_dst, FALSE);
        break;
      }
    }
    // Use llvm-symbolizer from Electron's toolchain
    // Build address input: PE preferred base (0x140000000) + RVA
    std::string addr_str;
    std::vector<uint64_t> dedup;
    for (auto addr : addrs) {
      uint64_t mbase = SymGetModuleBase64(proc, addr);
      if (!mbase) continue;
      bool dup = false;
      for (auto d : dedup) if (d == addr) { dup = true; break; }
      if (dup) continue;
      dedup.push_back(addr);
      uint64_t pva = 0x140000000ULL + (addr - mbase);
      char tmp[32]; snprintf(tmp, sizeof(tmp), "0x%llX\n", (unsigned long long)pva);
      addr_str += tmp;
    }
    if (!addr_str.empty()) {
      HANDLE hInR, hInW, hOutR, hOutW;
      SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
      CreatePipe(&hInR, &hInW, &sa, 0);
      CreatePipe(&hOutR, &hOutW, &sa, 0);
      SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);
      STARTUPINFOA si = { sizeof(si) };
      si.dwFlags = STARTF_USESTDHANDLES;
      si.hStdInput  = hInR;
      si.hStdOutput = hOutW;
      si.hStdError  = hOutW;
      PROCESS_INFORMATION pi = {};
      char cmd[1024];
      const char* llvm_sym = "llvm-symbolizer";
      // Prefer Electron's LLVM toolchain (same as build.bat uses for clang-cl)
      if (GetFileAttributesA("D:\\Codebase\\electron\\src\\third_party\\llvm-build\\Release+Asserts\\bin\\llvm-symbolizer.exe") != INVALID_FILE_ATTRIBUTES)
        llvm_sym = "\"D:\\Codebase\\electron\\src\\third_party\\llvm-build\\Release+Asserts\\bin\\llvm-symbolizer.exe\"";
      snprintf(cmd, sizeof(cmd),
        "%s --obj=\"%s\" --output-style=LLVM --functions=linkage",
        llvm_sym, exe_path.c_str());
      if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hOutW); CloseHandle(hInR);
        DWORD wx; WriteFile(hInW, addr_str.c_str(), (DWORD)addr_str.size(), &wx, NULL);
        CloseHandle(hInW);
        WaitForSingleObject(pi.hProcess, 30000);
        // Read output after process exits
        char obuf[65536] = {}; DWORD orx = 0;
        ReadFile(hOutR, obuf, sizeof(obuf) - 1, &orx, NULL);
        CloseHandle(hOutR);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        printf("  [llvm] output (%u bytes): %.200s\n", orx, obuf);
        // Parse: function\nsource\nblank...
        std::string out(obuf, orx);
        size_t pos = 0, ai = 0;
        while (pos < out.size() && ai < dedup.size()) {
          size_t nl1 = out.find('\n', pos);
          size_t nl2 = nl1 != std::string::npos ? out.find('\n', nl1 + 1) : std::string::npos;
          if (nl1 == std::string::npos) break;
          std::string func = out.substr(pos, nl1 - pos);
          std::string src;
          if (nl2 != std::string::npos) src = out.substr(nl1 + 1, nl2 - nl1 - 1);
          if (!func.empty() && func != "??") {
            sym_map[dedup[ai]] = func;
            if (!src.empty() && src != "??:0" && src != "??:0:0") src_map[dedup[ai]] = src;
          }
          pos = nl2 != std::string::npos ? nl2 + 1 : nl1 + 1;
          ai++;
        }
      } else {
        printf("  [llvm] CreateProcess FAILED cmd=%s\n", cmd);
        CloseHandle(hOutW); CloseHandle(hOutR); CloseHandle(hInW); CloseHandle(hInR);
      }
    }
  }

  // Step 3: display
  printf("=== Native Stack ===\n");
  for (size_t d = 0; d < addrs.size(); d++) {
    uint64_t addr = addrs[d];
    std::string r;
    auto sit = sym_map.find(addr);
    if (sit != sym_map.end()) {
      r = sit->second;
      auto src = src_map.find(addr);
      if (src != src_map.end()) r += " [" + src->second + "]";
    } else {
      r = resolve(addr);
      if (!r.empty() && r[0] == ' ') r = r.substr(1);
    }
    if (d == 0)
      printf("  #cr  | 0x%013llx | <crash> %s\n", (unsigned long long)addr, r.c_str());
    else
      printf("  #%02llu  | 0x%013llx | %s\n", (unsigned long long)d, (unsigned long long)addr, r.c_str());
  }
  printf("\n");
}

Sym::~Sym() {
  for (auto& p : dia_sessions) p.second->Release();
  for (auto& p : dia_sources) p.second->Release();
  CoUninitialize();
  if (ok) SymCleanup(proc);
}
