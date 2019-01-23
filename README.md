# pywinhv - Microsoft Hypervisor Platform APIs Python bindings

This repository provides Python bindings for the [Microsoft Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/) APIs.

## Overview

Microsoft has made available [a set of APIs](https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform) that allows to interact with the Hyper-V hypervisor. You can find them declared in `WinHvPlatform.h` / `WinHvEmulation.h` / `WinHvPlatformDefs.h` and implemented respectively in `WinHvPlatform.dll` / `WinHvEmulation.dll` / `VmSavedStateDumpProvider.dll`. The `pywinhv` Python bindings are generated using [SWIG](http://www.swig.org/) and built with Visual Studio 2017.

In order to enable the runtime support for the APIs you need to install the optional opt-in feature called *Windows Hypervisor Platform* as well as a Windows 10 with the *April 2018 Update* or above. You should be all set now!

## Examples

TODO.

```Python
import sys
from pywinhv import *

getsizeof = sys.getsizeof

def main(argc, argv):
    Capabilities = WHV_CAPABILITY()
    ReturnLength = new_PUINT32()
    PUINT32_assign(ReturnLength, 0)
    assert WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent,
        Capabilities,
        getsizeof(Capabilities),
        ReturnLength
    ) == 0, 'WHvGetCapability failed'

    print 'HyperviorPresent:', Capabilities.HypervisorPresent == 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
```



## Building

To compile the Python bindings you need to install the Windows 10.0.17134.0 SDK, Visual Studio 2017 (that is the only version I have personally tested) and [SWIG](http://www.swig.org/). Edit the file `build\Makefile` and update both the variables `PYTHON_INC` and `PYTHON_LIB` with appropriate paths.

Once this is done, open an *x64 Native Tools Command Prompt for VS2017* and run the following commands:

```text
(C:\ProgramData\Anaconda2) c:\work\codes\pywinhv>set SWIG_EXE=C:\Users\over\Downloads\swigwin-3.0.12\swigwin-3.0.12\swig.exe
(C:\ProgramData\Anaconda2) c:\work\codes\pywinhv>cd build
(C:\ProgramData\Anaconda2) c:\work\codes\pywinhv\build>nmake

Microsoft (R) Program Maintenance Utility Version 14.16.27026.1
Copyright (C) Microsoft Corporation.  All rights reserved.

        C:\Users\over\Downloads\swigwin-3.0.12\swigwin-3.0.12\swig.exe -v -Iinc -I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.17763.0\um" -I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.17763.0\shared" -outdir ..\pywinhv -o src\_pywinhv.c -python swig\_pywinhv.i
Language subdirectory: python
Search paths:
   .\
   inc\
   C:\Program Files (x86)\Windows Kits\10\Include\10.0.17763.0\um\
   C:\Program Files (x86)\Windows Kits\10\Include\10.0.17763.0\shared\
   .\swig_lib\python\
   C:\Users\over\Downloads\swigwin-3.0.12\swigwin-3.0.12\Lib\python\
   .\swig_lib\
   C:\Users\over\Downloads\swigwin-3.0.12\swigwin-3.0.12\Lib\
Preprocessing...
Starting language-specific parse...
[...]
Processing unnamed structs...
Processing types...
C++ analysis...
Generating wrappers...
        cl.exe /nologo /W3 /I C:\ProgramData\Anaconda2\include /I inc /D_AMD64_ /c src\_pywinhv.c /Fosrc\_pywinhv.c.o
_pywinhv.c
        link.exe /DLL /nologo /debug:full C:\ProgramData\Anaconda2\libs\python27.lib winhvplatform.lib winhvemulation.lib /out:_pywinhv.pyd src\_pywinhv.c.o
   Creating library _pywinhv.lib and object _pywinhv.exp
        copy _pywinhv.pyd ..\pywinhv
        1 file(s) copied.
Testing...
        python test.py
HyperviorPresent: True
```

## Binaries

TODO.
