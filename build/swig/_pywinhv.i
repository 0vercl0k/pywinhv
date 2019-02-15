// Axel '0vercl0k' Souchet - 20 January 2019
%module pywinhv
%{
    #include <WinHvPlatform.h>
    #include <WinHvEmulation.h>
    #include <Extras.h>
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

// For dealing with __stdcall (CALLBACK, WINAPI).
#define CALLBACK __stdcall
%include windows.i

// Ugly but tells SWIG to generate proxy functions to create various pointers.
// XXX: Use typemaps.
%include cpointer.i
%pointer_functions(UINT32, PUINT32)
%pointer_functions(UINT64, PUINT64)
%pointer_functions(WHV_PARTITION_HANDLE, PWHV_PARTITION_HANDLE)

// This is required to set WINAPI_FAMILY to the proper value when preprocessing
// the WinHv header files.
%include <winapifamily.h>
%include <WinHvPlatformDefs.h>
%include <WinHvPlatform.h>
%include <WinHvEmulation.h>
%include <Extras.h>

// Expose a way to get the sizeof various types from Python.
%extend WHV_RUN_VP_EXIT_CONTEXT {
    size_t __len__() {
        return sizeof(*$self);
    }
}

%extend WHV_CAPABILITY {
    size_t __len__() {
        return sizeof(*$self);
    }
}

%extend WHV_PARTITION_PROPERTY {
    size_t __len__() {
        return sizeof(*$self);
    }
}

%extend WHV_REGISTER_VALUE {
    size_t __len__() {
        return sizeof(*$self);
    }
}

%extend WHV_PARTITION_MEMORY_COUNTERS {
    size_t __len__() {
        return sizeof(*$self);
    }
}

%extend WHV_PROCESSOR_ALL_COUNTERS  {
    size_t __len__() {
        return sizeof(*$self);
    }
}

// Expose functions to create WHV_REGISTER_NAME / WHV_REGISTER_VALUE arrays.
%include carrays.i
%array_class(WHV_REGISTER_NAME, WHV_REGISTER_NAME_ARRAY)
%array_class(WHV_REGISTER_VALUE, WHV_REGISTER_VALUE_ARRAY)
%array_class(UINT64, UINT64_ARRAY)

// Expose a method to convert PVOID into a uintptr_t integer (useful for WHvMapGpaRange for example).
%pointer_cast(unsigned long long, void*, uint2pvoid);

