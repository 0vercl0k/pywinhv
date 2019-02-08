# Axel '0vercl0k' Souchet - 23 January 2019
import pywinhv as whv
import ctypes as ct
from ctypes.wintypes import LPVOID, DWORD, c_size_t as SIZE_T
import sys
from enum import Enum

# X64 General purpose registers
Rax = whv.WHvX64RegisterRax
Rcx = whv.WHvX64RegisterRcx
Rdx = whv.WHvX64RegisterRdx
Rbx = whv.WHvX64RegisterRbx
Rsp = whv.WHvX64RegisterRsp
Rbp = whv.WHvX64RegisterRbp
Rsi = whv.WHvX64RegisterRsi
Rdi = whv.WHvX64RegisterRdi
R8 = whv.WHvX64RegisterR8
R9 = whv.WHvX64RegisterR9
R10 = whv.WHvX64RegisterR10
R11 = whv.WHvX64RegisterR11
R12 = whv.WHvX64RegisterR12
R13 = whv.WHvX64RegisterR13
R14 = whv.WHvX64RegisterR14
R15 = whv.WHvX64RegisterR15
Rip = whv.WHvX64RegisterRip
Rflags = whv.WHvX64RegisterRflags

# X64 Segment registers
Es = whv.WHvX64RegisterEs
Cs = whv.WHvX64RegisterCs
Ss = whv.WHvX64RegisterSs
Ds = whv.WHvX64RegisterDs
Fs = whv.WHvX64RegisterFs
Gs = whv.WHvX64RegisterGs
Ldtr = whv.WHvX64RegisterLdtr
Tr = whv.WHvX64RegisterTr

# X64 Table registers
Idtr = whv.WHvX64RegisterIdtr
Gdtr = whv.WHvX64RegisterGdtr

# X64 Control Registers
Cr0 = whv.WHvX64RegisterCr0
Cr2 = whv.WHvX64RegisterCr2
Cr3 = whv.WHvX64RegisterCr3
Cr4 = whv.WHvX64RegisterCr4
Cr8 = whv.WHvX64RegisterCr8

# X64 Debug Registers
Dr0 = whv.WHvX64RegisterDr0
Dr1 = whv.WHvX64RegisterDr1
Dr2 = whv.WHvX64RegisterDr2
Dr3 = whv.WHvX64RegisterDr3
Dr6 = whv.WHvX64RegisterDr6
Dr7 = whv.WHvX64RegisterDr7

# X64 Extended Control Registers
XCr0 = whv.WHvX64RegisterXCr0

# X64 Floating Point and Vector Registers
Xmm0 = whv.WHvX64RegisterXmm0
Xmm1 = whv.WHvX64RegisterXmm1
Xmm2 = whv.WHvX64RegisterXmm2
Xmm3 = whv.WHvX64RegisterXmm3
Xmm4 = whv.WHvX64RegisterXmm4
Xmm5 = whv.WHvX64RegisterXmm5
Xmm6 = whv.WHvX64RegisterXmm6
Xmm7 = whv.WHvX64RegisterXmm7
Xmm8 = whv.WHvX64RegisterXmm8
Xmm9 = whv.WHvX64RegisterXmm9
Xmm10 = whv.WHvX64RegisterXmm10
Xmm11 = whv.WHvX64RegisterXmm11
Xmm12 = whv.WHvX64RegisterXmm12
Xmm13 = whv.WHvX64RegisterXmm13
Xmm14 = whv.WHvX64RegisterXmm14
Xmm15 = whv.WHvX64RegisterXmm15
FpMmx0 = whv.WHvX64RegisterFpMmx0
FpMmx1 = whv.WHvX64RegisterFpMmx1
FpMmx2 = whv.WHvX64RegisterFpMmx2
FpMmx3 = whv.WHvX64RegisterFpMmx3
FpMmx4 = whv.WHvX64RegisterFpMmx4
FpMmx5 = whv.WHvX64RegisterFpMmx5
FpMmx6 = whv.WHvX64RegisterFpMmx6
FpMmx7 = whv.WHvX64RegisterFpMmx7
FpControlStatus = whv.WHvX64RegisterFpControlStatus
XmmControlStatus = whv.WHvX64RegisterXmmControlStatus

# X64 MSRs
Tsc = whv.WHvX64RegisterTsc
Efer = whv.WHvX64RegisterEfer
KernelGsBase = whv.WHvX64RegisterKernelGsBase
ApicBase = whv.WHvX64RegisterApicBase
Pat = whv.WHvX64RegisterPat
SysenterCs = whv.WHvX64RegisterSysenterCs
SysenterEip = whv.WHvX64RegisterSysenterEip
SysenterEsp = whv.WHvX64RegisterSysenterEsp
Star = whv.WHvX64RegisterStar
Lstar = whv.WHvX64RegisterLstar
Cstar = whv.WHvX64RegisterCstar
Sfmask = whv.WHvX64RegisterSfmask

MsrMtrrCap = whv.WHvX64RegisterMsrMtrrCap
MsrMtrrDefType = whv.WHvX64RegisterMsrMtrrDefType

MsrMtrrPhysBase0 = whv.WHvX64RegisterMsrMtrrPhysBase0
MsrMtrrPhysBase1 = whv.WHvX64RegisterMsrMtrrPhysBase1
MsrMtrrPhysBase2 = whv.WHvX64RegisterMsrMtrrPhysBase2
MsrMtrrPhysBase3 = whv.WHvX64RegisterMsrMtrrPhysBase3
MsrMtrrPhysBase4 = whv.WHvX64RegisterMsrMtrrPhysBase4
MsrMtrrPhysBase5 = whv.WHvX64RegisterMsrMtrrPhysBase5
MsrMtrrPhysBase6 = whv.WHvX64RegisterMsrMtrrPhysBase6
MsrMtrrPhysBase7 = whv.WHvX64RegisterMsrMtrrPhysBase7
MsrMtrrPhysBase8 = whv.WHvX64RegisterMsrMtrrPhysBase8
MsrMtrrPhysBase9 = whv.WHvX64RegisterMsrMtrrPhysBase9
MsrMtrrPhysBaseA = whv.WHvX64RegisterMsrMtrrPhysBaseA
MsrMtrrPhysBaseB = whv.WHvX64RegisterMsrMtrrPhysBaseB
MsrMtrrPhysBaseC = whv.WHvX64RegisterMsrMtrrPhysBaseC
MsrMtrrPhysBaseD = whv.WHvX64RegisterMsrMtrrPhysBaseD
MsrMtrrPhysBaseE = whv.WHvX64RegisterMsrMtrrPhysBaseE
MsrMtrrPhysBaseF = whv.WHvX64RegisterMsrMtrrPhysBaseF

MsrMtrrPhysMask0 = whv.WHvX64RegisterMsrMtrrPhysMask0
MsrMtrrPhysMask1 = whv.WHvX64RegisterMsrMtrrPhysMask1
MsrMtrrPhysMask2 = whv.WHvX64RegisterMsrMtrrPhysMask2
MsrMtrrPhysMask3 = whv.WHvX64RegisterMsrMtrrPhysMask3
MsrMtrrPhysMask4 = whv.WHvX64RegisterMsrMtrrPhysMask4
MsrMtrrPhysMask5 = whv.WHvX64RegisterMsrMtrrPhysMask5
MsrMtrrPhysMask6 = whv.WHvX64RegisterMsrMtrrPhysMask6
MsrMtrrPhysMask7 = whv.WHvX64RegisterMsrMtrrPhysMask7
MsrMtrrPhysMask8 = whv.WHvX64RegisterMsrMtrrPhysMask8
MsrMtrrPhysMask9 = whv.WHvX64RegisterMsrMtrrPhysMask9
MsrMtrrPhysMaskA = whv.WHvX64RegisterMsrMtrrPhysMaskA
MsrMtrrPhysMaskB = whv.WHvX64RegisterMsrMtrrPhysMaskB
MsrMtrrPhysMaskC = whv.WHvX64RegisterMsrMtrrPhysMaskC
MsrMtrrPhysMaskD = whv.WHvX64RegisterMsrMtrrPhysMaskD
MsrMtrrPhysMaskE = whv.WHvX64RegisterMsrMtrrPhysMaskE
MsrMtrrPhysMaskF = whv.WHvX64RegisterMsrMtrrPhysMaskF

MsrMtrrFix64k00000 = whv.WHvX64RegisterMsrMtrrFix64k00000
MsrMtrrFix16k80000 = whv.WHvX64RegisterMsrMtrrFix16k80000
MsrMtrrFix16kA0000 = whv.WHvX64RegisterMsrMtrrFix16kA0000
MsrMtrrFix4kC0000 = whv.WHvX64RegisterMsrMtrrFix4kC0000
MsrMtrrFix4kC8000 = whv.WHvX64RegisterMsrMtrrFix4kC8000
MsrMtrrFix4kD0000 = whv.WHvX64RegisterMsrMtrrFix4kD0000
MsrMtrrFix4kD8000 = whv.WHvX64RegisterMsrMtrrFix4kD8000
MsrMtrrFix4kE0000 = whv.WHvX64RegisterMsrMtrrFix4kE0000
MsrMtrrFix4kE8000 = whv.WHvX64RegisterMsrMtrrFix4kE8000
MsrMtrrFix4kF0000 = whv.WHvX64RegisterMsrMtrrFix4kF0000
MsrMtrrFix4kF8000 = whv.WHvX64RegisterMsrMtrrFix4kF8000

TscAux = whv.WHvX64RegisterTscAux
SpecCtrl = whv.WHvX64RegisterSpecCtrl
PredCmd = whv.WHvX64RegisterPredCmd

# APIC state (also accessible via WHv(Get/Set)VirtualProcessorInterruptControllerState)
ApicId = whv.WHvX64RegisterApicId
ApicVersion = whv.WHvX64RegisterApicVersion

# Interrupt / Event Registers
RegisterPendingInterruption = whv.WHvRegisterPendingInterruption
RegisterInterruptState = whv.WHvRegisterInterruptState
RegisterPendingEvent = whv.WHvRegisterPendingEvent
DeliverabilityNotifications = whv.WHvX64RegisterDeliverabilityNotifications
RegisterInternalActivityState = whv.WHvRegisterInternalActivityState

def WHvGetCapability(CapabilityCode, CapabilityBuffer):
    '''
    HRESULT
    WINAPI
    WHvGetCapability(
        _In_ WHV_CAPABILITY_CODE CapabilityCode,
        _Out_writes_bytes_to_(CapabilityBufferSizeInBytes,*WrittenSizeInBytes) VOID* CapabilityBuffer,
        _In_ UINT32 CapabilityBufferSizeInBytes,
        _Out_opt_ UINT32* WrittenSizeInBytes
        );

    Platform capabilities are a generic way for callers to query properties and
    capabilities of the hypervisor, of the API implementation, and of the hardware
    platform that the application is running on. The platform API uses these capabilities
    to publish the availability of extended functionality of the API as well as the set
    of features that the processor on the current system supports. Applications must
    query the availability of a feature prior to calling the corresponding APIs or
    allowing a VM to use a processor feature.
    '''
    CapabilityBufferSize = len(CapabilityBuffer)
    ReturnLength = whv.new_PUINT32()
    whv.PUINT32_assign(ReturnLength, 0)
    Ret = whv.WHvGetCapability(
        CapabilityCode,
        CapabilityBuffer,
        CapabilityBufferSize,
        ReturnLength
    )

    Success = Ret == 0
    ReturnLengthValue = whv.PUINT32_value(ReturnLength)
    if Success:
        # On a success we make sure the ReturnLength matches.
        Success = ReturnLengthValue <= CapabilityBufferSize

    # Release the ReturnLength pointer.
    whv.delete_PUINT32(ReturnLength)
    return (Success, ReturnLengthValue, Ret & 0xffffffff)

def WHvCreatePartition():
    '''
    HRESULT
    WINAPI
    WHvCreatePartition(
        _Out_ WHV_PARTITION_HANDLE* Partition
        );

    The WHvCreatePartition function creates a new partition object.
    Creating the file object does not yet create the actual partition in the hypervisor.
    To create the hypervisor partition, the WHvSetupPartition function needs to be called.
    Additional properties of the partition can be configured prior to this call;
    these properties are stored in the partition object in the VID and are applied when
    creating the partition in the hypervisor.
    '''
    Partition = whv.new_PWHV_PARTITION_HANDLE()
    Ret = whv.WHvCreatePartition(Partition)

    Success = Ret == 0
    PartitionValue = whv.PWHV_PARTITION_HANDLE_value(Partition)
    if not Success:
        PartitionValue = None

    # Release the Partition pointer.
    whv.delete_PWHV_PARTITION_HANDLE(Partition)
    return (Success, PartitionValue, Ret & 0xffffffff)

def WHvDeletePartition(Partition):
    '''
    HRESULT
    WINAPI
    WHvDeletePartition(
        _In_ WHV_PARTITION_HANDLE Partition
        );

    Deleting a partition tears down the partition object and releases all resource that
    the partition was using.
    '''
    Ret = whv.WHvDeletePartition(Partition)

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvSetupPartition(Partition):
    '''
    HRESULT
    WINAPI
    WHvSetupPartition(
        _In_ WHV_PARTITION_HANDLE Partition
        );

    Setting up the partition causes the actual partition to be created in the hypervisor.
    A partition needs to be set up prior to performing any other operation on the
    partition after it was created by WHvCreatePartition, with exception of calling
    WHvSetPartitionProperty to configure the initial properties of the partition.
    '''
    Ret = whv.WHvSetupPartition(Partition)

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvSetPartitionProperty(Partition, PropertyCode, PropertyBuffer):
    '''
    HRESULT
    WINAPI
    WHvSetPartitionProperty(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ WHV_PARTITION_PROPERTY_CODE PropertyCode,
        _In_reads_bytes_(PropertyBufferSizeInBytes) const VOID* PropertyBuffer,
        _In_ UINT32 PropertyBufferSizeInBytes
        );
    '''
    PropertyBufferSizeInBytes = len(PropertyBuffer)
    Ret = whv.WHvSetPartitionProperty(
        Partition,
        PropertyCode,
        PropertyBuffer,
        PropertyBufferSizeInBytes
    )

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvCreateVirtualProcessor(Partition, VpIndex):
    '''
    HRESULT
    WINAPI
    WHvCreateVirtualProcessor(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ UINT32 VpIndex,
        _In_ UINT32 Flags
        );

    The WHvCreateVirtualProcessor function creates a new virtual processor in a
    partition. The index of the virtual processor is used to set the APIC ID of the
    processor.
    '''
    Ret = whv.WHvCreateVirtualProcessor(
        Partition,
        VpIndex,
        0
    )

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvDeleteVirtualProcessor(Partition, VpIndex):
    '''
    HRESULT
    WINAPI
    WHvDeleteVirtualProcessor(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ UINT32 VpIndex
        );

    The WHvDeleteVirtualProcessor function deletes a virtual processor in a partition.
    '''
    Ret = whv.WHvDeleteVirtualProcessor(
        Partition,
        VpIndex
    )

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvRunVirtualProcessor(Partition, VpIndex):
    '''
    HRESULT
    WINAPI
    WHvRunVirtualProcessor(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ UINT32 VpIndex,
        _Out_writes_bytes_(ExitContextSizeInBytes) VOID* ExitContext,
        _In_ UINT32 ExitContextSizeInBytes
        );

    A virtual processor is executed (i.e., is enabled to run guest code) by making a
    call to the WHvRunVirtualProcessor function. A call to this function blocks
    synchronously until either the virtual processor executed an operation that needs
    to be handled by the virtualization stack (e.g., accessed memory in the GPA space
    that is not mapped or not accessible) or the virtualization stack explicitly
    request an exit of the function (e.g., to inject an interrupt for the virtual
    processor or to change the state of the VM).
    '''
    ExitContext = whv.WHV_RUN_VP_EXIT_CONTEXT()
    ExitContextSizeInBytes = len(ExitContext)
    Ret = whv.WHvRunVirtualProcessor(
        Partition,
        VpIndex,
        ExitContext,
        ExitContextSizeInBytes
    )

    Success = Ret == 0
    return (Success, ExitContext, Ret & 0xffffffff)

def WHvGetVirtualProcessorRegisters(Partition, VpIndex, Registers):
    '''
    HRESULT
    WINAPI
    WHvGetVirtualProcessorRegisters(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ UINT32 VpIndex,
        _In_reads_(RegisterCount) const WHV_REGISTER_NAME* RegisterNames,
        _In_ UINT32 RegisterCount,
        _Out_writes_(RegisterCount) WHV_REGISTER_VALUE* RegisterValues
        );
    '''
    RegisterCount = len(Registers)
    RegisterNames = whv.WHV_REGISTER_NAME_ARRAY(RegisterCount)
    for Idx, RegisterName in enumerate(Registers):
        RegisterNames[Idx] = RegisterName

    RegisterValues = whv.WHV_REGISTER_VALUE_ARRAY(RegisterCount)
    Ret = whv.WHvGetVirtualProcessorRegisters(
        Partition,
        VpIndex,
        RegisterNames.cast(),
        RegisterCount,
        RegisterValues.cast()
    )

    Success = Ret == 0
    Values = []
    if Success:
        for Idx in range(RegisterCount):
            Values.append(RegisterValues[Idx])

    return (Success, Values, Ret & 0xffffffff)

def WHvSetVirtualProcessorRegisters(Partition, VpIndex, Registers):
    '''
    HRESULT
    WINAPI
    WHvSetVirtualProcessorRegisters(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ UINT32 VpIndex,
        _In_reads_(RegisterCount) const WHV_REGISTER_NAME* RegisterNames,
        _In_ UINT32 RegisterCount,
        _In_reads_(RegisterCount) const WHV_REGISTER_VALUE* RegisterValues
        );
    '''
    RegisterCount = len(Registers)
    RegisterNames = whv.WHV_REGISTER_NAME_ARRAY(RegisterCount)
    RegisterValues = whv.WHV_REGISTER_VALUE_ARRAY(RegisterCount)
    for Idx, NameValue in enumerate(Registers.iteritems()):
        Name, Value = NameValue
        RegisterNames[Idx] = Name
        # Note: We cannot initialize the array using the 'RegisterValues[Idx].Reg64 = x'
        # construct because the WHV_REGISTER_NAME_ARRAY__getitem__ routines returns
        # a copy (new buffer) instead of a pointer to the structure we want to initialize.
        # What this mean is that the above statement end up not initializing RegisterValues[Idx]
        # but a copy of it. Kinda annoying.
        if isinstance(Value, whv.WHV_REGISTER_VALUE):
            RegisterValue = Value
        else:
            RegisterValue = whv.WHV_REGISTER_VALUE()
            RegisterValue.Reg64 = Value
        RegisterValues[Idx] = RegisterValue

    Ret = whv.WHvSetVirtualProcessorRegisters(
        Partition,
        VpIndex,
        RegisterNames.cast(),
        RegisterCount,
        RegisterValues.cast()
    )

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvMapGpaRange(Partition, SourceAddress, GuestAddress, SizeInBytes, FlagsStr):
    '''
    HRESULT
    WINAPI
    WHvMapGpaRange(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ VOID* SourceAddress,
        _In_ WHV_GUEST_PHYSICAL_ADDRESS GuestAddress,
        _In_ UINT64 SizeInBytes,
        _In_ WHV_MAP_GPA_RANGE_FLAGS Flags
        );

    Creating a mapping for a range in the GPA space of a partition sets a region in the
    caller's process as the backing memory for that range. The operation replaces any
    previous mappings for the specified GPA pages.
    '''
    FlagsStr = FlagsStr.lower()
    Flags = whv.WHvMapGpaRangeFlagNone
    if 'r' in FlagsStr:
        Flags |= whv.WHvMapGpaRangeFlagRead

    if 'w' in FlagsStr:
        Flags |= whv.WHvMapGpaRangeFlagWrite

    if 'x' in FlagsStr:
        Flags |= whv.WHvMapGpaRangeFlagExecute

    if 'd' in FlagsStr:
        Flags |= whv.WHvMapGpaRangeFlagTrackDirtyPages

    assert (SourceAddress & 0xfff) == 0, 'SourceAddress(%x) needs to be page aligned.' % SourceAddress
    assert (SizeInBytes % 0x1000) == 0, 'SizeInBytes(%x) needs to be page aligned.' % SizeInBytes

    Ret = whv.WHvMapGpaRange(
        Partition,
        whv.uint2pvoid(SourceAddress),
        GuestAddress,
        SizeInBytes,
        Flags
    )

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvUnmapGpaRange(Partition, GuestAddress, SizeInBytes):
    '''
    HRESULT
    WINAPI
    WHvUnmapGpaRange(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ WHV_GUEST_PHYSICAL_ADDRESS GuestAddress,
        _In_ UINT64 SizeInBytes
        );

    Unmapping a previously mapped GPA range makes the memory range unavailable to the
    partition. Any further access by a virtual processor to the range will result in a
    memory access exit.
    '''
    assert (SourceAddress & 0xfff) == 0, 'SourceAddress(%x) needs to be page aligned.' % SourceAddress
    assert (SizeInBytes % 0x1000) == 0, 'SizeInBytes(%x) needs to be page aligned.' % SizeInBytes

    Ret = whv.WHvUnmapGpaRange(
        Partition,
        whv.uint2pvoid(GuestAddress),
        SizeInBytes,
    )

    Success = Ret == 0
    return (Success, Ret & 0xffffffff)

def WHvTranslateGva(Partition, VpIndex, Gva, TranslateFlags):
    '''
    HRESULT
    WINAPI
    WHvTranslateGva(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ UINT32 VpIndex,
        _In_ WHV_GUEST_VIRTUAL_ADDRESS Gva,
        _In_ WHV_TRANSLATE_GVA_FLAGS TranslateFlags,
        _Out_ WHV_TRANSLATE_GVA_RESULT* TranslationResult,
        _Out_ WHV_GUEST_PHYSICAL_ADDRESS* Gpa
        );

    Translating a virtual address used by a virtual processor in a partition allows
    the virtualization stack to emulate a processor instruction for an I/O operation,
    using the results of the translation to read and write the memory operands of the
    instruction in the GPA space of the partition.

    The hypervisor performs the translating by walking the page table that is
    currently active for the virtual processor. The translation can fail if the page
    table is not accessible, in which case an appropriate page fault needs to be
    injected into the virtual processor by the virtualization stack.
    '''

    TranslationResult = whv.WHV_TRANSLATE_GVA_RESULT()
    Gpa = whv.new_PUINT64()
    Ret = whv.WHvTranslateGva(
        Partition,
        VpIndex,
        Gva,
        TranslateFlags,
        TranslationResult,
        Gpa
    )

    GpaValue = whv.PUINT64_value(Gpa)
    Success = Ret == 0
    # Release the UINT64 pointer.
    whv.delete_PUINT64(Gpa)
    return (Success, TranslationResult.ResultCode, GpaValue, Ret & 0xffffffff)

def WHvGetPartitionCounters(Partition, CounterSet):
    '''
    HRESULT
    WINAPI
    WHvGetPartitionCounters(
        _In_ WHV_PARTITION_HANDLE Partition,
        _In_ WHV_PARTITION_COUNTER_SET CounterSet,
        _Out_writes_bytes_to_(BufferSizeInBytes,*BytesWritten) VOID* Buffer,
        _In_ UINT32 BufferSizeInBytes,
        _Out_opt_ UINT32* BytesWritten
        );
    '''
    Buffer = whv.WHV_PARTITION_MEMORY_COUNTERS()
    BufferSizeInBytes = len(Buffer)
    BytesWritten = whv.new_PUINT32()
    Ret = whv.WHvGetPartitionCounters(
        Partition,
        CounterSet,
        Buffer,
        BufferSizeInBytes,
        BytesWritten
    )

    Success = Ret == 0
    # Release the UINT32 pointer.
    whv.delete_PUINT32(BytesWritten)
    return (Success, Buffer, Ret & 0xffffffff)

class WHvExitReason(Enum):
    WHvRunVpExitReasonNone = 0x00000000
    WHvRunVpExitReasonMemoryAccess = 0x00000001
    WHvRunVpExitReasonX64IoPortAccess = 0x00000002
    WHvRunVpExitReasonUnrecoverableException = 0x00000004
    WHvRunVpExitReasonInvalidVpRegisterValue = 0x00000005
    WHvRunVpExitReasonUnsupportedFeature = 0x00000006
    WHvRunVpExitReasonX64InterruptWindow = 0x00000007
    WHvRunVpExitReasonX64Halt = 0x00000008
    WHvRunVpExitReasonX64ApicEoi = 0x00000009
    WHvRunVpExitReasonX64MsrAccess = 0x00001000
    WHvRunVpExitReasonX64Cpuid = 0x00001001
    WHvRunVpExitReasonException = 0x00001002
    WHvRunVpExitReasonCanceled = 0x00002001

class WHvTranslateGvaResultCode(Enum):
    WHvTranslateGvaResultSuccess                 = 0
    WHvTranslateGvaResultPageNotPresent          = 1
    WHvTranslateGvaResultPrivilegeViolation      = 2
    WHvTranslateGvaResultInvalidPageTableFlags   = 3
    WHvTranslateGvaResultGpaUnmapped             = 4
    WHvTranslateGvaResultGpaNoReadAccess         = 5
    WHvTranslateGvaResultGpaNoWriteAccess        = 6
    WHvTranslateGvaResultGpaIllegalOverlayAccess = 7
    WHvTranslateGvaResultIntercept               = 8

def main(argc, argv):
    StructSizes = {
        whv.WHV_RUN_VP_EXIT_CONTEXT : 144,
        whv.WHV_CAPABILITY : 8,
        whv.WHV_PARTITION_PROPERTY : 32,
        whv.WHV_REGISTER_VALUE : 16,
        whv.WHV_PARTITION_MEMORY_COUNTERS : 24 
    }

    for Struct, StructSize in StructSizes.iteritems():
        Success = len(Struct()) == StructSize
        print 'sizeof(%s) == %d: %r' % (Struct.__name__, StructSize, Success)
        if not Success:
            return 1

    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))


