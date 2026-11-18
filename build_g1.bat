@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
msbuild simplewall.sln -property:Configuration=Release -property:Platform=x64 -property:PlatformToolset=v143 -property:OutDir=D:\CV\Github\simplewall\bin\mergetest\ -verbosity:minimal -m
