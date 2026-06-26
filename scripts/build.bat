@echo off
REM V8-DumpAnalyzer build script
setlocal
set ROOT=%~dp0..
set SRCDIR=%ROOT%\src
set OUTDIR=%ROOT%\out

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

REM Try clang-cl from Electron build if available
set CC=cl.exe
if exist "D:\Codebase\electron\src\third_party\llvm-build\Release+Asserts\bin\clang-cl.exe" (
  set CC="D:\Codebase\electron\src\third_party\llvm-build\Release+Asserts\bin\clang-cl.exe"
)

echo Compiler: %CC%

set DIADIR=C:\Program Files\Microsoft Visual Studio\2022\Community\DIA SDK
set DIAINC=%DIADIR%\include
set DIALIB=%DIADIR%\lib\amd64\diaguids.lib
set CFLAGS=/nologo /O2 /MT /W4 /std:c++17 /D_CRT_SECURE_NO_WARNINGS /EHsc /I"%SRCDIR%" /I"%DIAINC%"

%CC% %CFLAGS% /c "%SRCDIR%\main.cpp"       /Fo"%OUTDIR%\main.obj"
if errorlevel 1 exit /b %errorlevel%
%CC% %CFLAGS% /c "%SRCDIR%\minidump_reader.cpp" /Fo"%OUTDIR%\minidump_reader.obj"
if errorlevel 1 exit /b %errorlevel%
%CC% %CFLAGS% /c "%SRCDIR%\symbol_resolver.cpp" /Fo"%OUTDIR%\symbol_resolver.obj"
if errorlevel 1 exit /b %errorlevel%
%CC% %CFLAGS% /c "%SRCDIR%\v8_scan.cpp"    /Fo"%OUTDIR%\v8_scan.obj"
if errorlevel 1 exit /b %errorlevel%

echo Linking...
%CC% /nologo "%OUTDIR%\main.obj" "%OUTDIR%\minidump_reader.obj" "%OUTDIR%\symbol_resolver.obj" "%OUTDIR%\v8_scan.obj" /Fe"%OUTDIR%\dump_analyzer.exe" "%DIALIB%" ole32.lib

echo.
echo Done: %OUTDIR%\dump_analyzer.exe
echo Test: %OUTDIR%\dump_analyzer.exe crash.dmp
