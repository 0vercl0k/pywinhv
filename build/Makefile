# Axel '0vercl0k' Souchet - 20 January 2019

CC = cl.exe
LD = link.exe

PYTHON_INC = C:\ProgramData\Anaconda2\include
PYTHON_LIB = C:\ProgramData\Anaconda2\libs

BASE_SDK = C:\Program Files (x86)\Windows Kits\10\Include\$(WINDOWSSDKLIBVERSION)

CFLAGS = /nologo /W3 /I $(PYTHON_INC) /I inc /D_AMD64_
LDFLAGS = /DLL /nologo /debug:full $(PYTHON_LIB)\python27.lib winhvplatform.lib winhvemulation.lib

all: _pywinhv.pyd test

# XXX: technically from the VS shell we already have $(INCLUDE) which is a
# comma separated string with all the include folders. Thing is, SWIG doesn't
# sound to like it.
src\_pywinhv.c:
    $(SWIG_EXE) -v -Iinc -I"$(BASE_SDK)um" -I"$(BASE_SDK)shared" -outdir ..\pywinhv -o src\_pywinhv.c -python swig\_pywinhv.i

src\_pywinhv.c.o: src\_pywinhv.c
    $(CC) $(CFLAGS) /c $** /Fo$@

_pywinhv.pyd: src\_pywinhv.c.o
    $(LD) $(LDFLAGS) /out:$@ $**
    copy $@ ..\pywinhv

.PHONY: test
test: _pywinhv.pyd
    @echo Testing...
    python ..\pywinhv\winhvplatform.py
    python ..\test64.py
    python ..\test32.py

.PHONY: clean
clean:
    -del _pywinhv.pyd *.o *.pdb *.ilk *.exp *.lib src\_pywinhv.c
