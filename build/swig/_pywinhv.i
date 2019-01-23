// Axel '0vercl0k' Souchet - 20 January 2019
%module pywinhv
%{
    #include <WinHvPlatform.h>
    #include <WinHvEmulation.h>
%}

// Suppress SAL annotations.
#define _In_ /**/
#define _Out_writes_bytes_to_(...) /**/
#define _In_reads_bytes_(...) /**/
#define _Out_opt_ /**/
#define _Out_ /**/
#define _Out_writes_bytes_(...) /**/
#define _In_reads_(...) /**/
#define _Out_writes_(...) /**/
#define _Out_writes_bytes_to_opt_(...) /**/
#define _Inout_ /**/
#define VOID void

#define C_ASSERT(...) /**/

// XXX: fix
#define DECLSPEC_ALIGN(...) /**/

// Ugly but tells SWIG to generate proxy functions to create UINT32 pointers.
// XXX: Use typemaps.
%include cpointer.i
%pointer_functions(UINT32, PUINT32)

// For dealing with __stdcall.
#define CALLBACK __stdcall
%include windows.i

// This is required to set WINAPI_FAMILY to the proper values when preprocessing
// the below files.
%include <winapifamily.h>
%include <WinHvPlatformDefs.h>
%include <WinHvPlatform.h>
%include <WinHvEmulation.h>
