// Axel '0vercl0k' Souchet - 4 Feb 2019
#include <windows.h>

typedef struct {
    union {
        struct {
            UINT64 Present : 1;
            UINT64 Write : 1;
            UINT64 UserAccessible : 1;
            UINT64 WriteThrough : 1;
            UINT64 CacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 LargePage : 1;
            UINT64 Available : 4;
            UINT64 PageFrameNumber : 36;
            UINT64 ReservedForHardware : 4;
            UINT64 ReservedForSoftware : 11;
            UINT64 NoExecute : 1;
        };
        UINT64 AsUINT64;
    };
} MMPTE_HARDWARE;
