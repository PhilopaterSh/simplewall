@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
dumpbin /nologo /disasm "D:\CV\Github\simplewall\bin\64\simplewall.exe" > "D:\CV\Github\simplewall\bin\64\disasm.txt" 2>&1
echo DISASM-DONE >> "D:\CV\Github\simplewall\bin\64\disasm.txt"
