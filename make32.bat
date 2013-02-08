@echo off

IF EXIST "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" call "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" x86
IF EXIST "C:\Program Files (x86)\Microsoft Visual Studio 11.0\VC\vcvarsall.bat" call "C:\Program Files (x86)\Microsoft Visual Studio 11.0\VC\vcvarsall.bat" x86
nmake /f Makefile.nmake
