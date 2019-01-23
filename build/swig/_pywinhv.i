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

// Suppress a few macros not supported (__declspec(align())) / defined in the
// context of the SWIG preprocessor.
#define C_ASSERT(...) /**/
#define DECLSPEC_ALIGN(...) /**/

// Ugly but tells SWIG to generate proxy functions to create UINT32 pointers.
// XXX: Use typemaps.
%include cpointer.i
%pointer_functions(UINT32, PUINT32)

// For dealing with __stdcall (CALLBACK, WINAPI).
#define CALLBACK __stdcall
%include windows.i

// This is required to set WINAPI_FAMILY to the proper value when preprocessing
// the WinHv header files.
%include <winapifamily.h>
%include <WinHvPlatformDefs.h>
%include <WinHvPlatform.h>
%include <WinHvEmulation.h>
