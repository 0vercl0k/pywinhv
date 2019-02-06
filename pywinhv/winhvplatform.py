# Axel '0vercl0k' Souchet - 23 January 2019
import pywinhv as whv
import ctypes as ct
from ctypes.wintypes import LPVOID, DWORD, c_size_t as SIZE_T
import sys
from enum import Enum

ct.windll.kernel32.VirtualAlloc.argtypes = (LPVOID, SIZE_T, DWORD, DWORD)
ct.windll.kernel32.VirtualAlloc.restype = LPVOID
VirtualAlloc = ct.windll.kernel32.VirtualAlloc

# X64 General purpose registers
_Rax = whv.WHvX64RegisterRax
_Rcx = whv.WHvX64RegisterRcx
_Rdx = whv.WHvX64RegisterRdx
_Rbx = whv.WHvX64RegisterRbx
_Rsp = whv.WHvX64RegisterRsp
_Rbp = whv.WHvX64RegisterRbp
_Rsi = whv.WHvX64RegisterRsi
_Rdi = whv.WHvX64RegisterRdi
_R8 = whv.WHvX64RegisterR8
_R9 = whv.WHvX64RegisterR9
_R10 = whv.WHvX64RegisterR10
_R11 = whv.WHvX64RegisterR11
_R12 = whv.WHvX64RegisterR12
_R13 = whv.WHvX64RegisterR13
_R14 = whv.WHvX64RegisterR14
_R15 = whv.WHvX64RegisterR15
_Rip = whv.WHvX64RegisterRip
_Rflags = whv.WHvX64RegisterRflags

# X64 Segment registers
_Es = whv.WHvX64RegisterEs
_Cs = whv.WHvX64RegisterCs
_Ss = whv.WHvX64RegisterSs
_Ds = whv.WHvX64RegisterDs
_Fs = whv.WHvX64RegisterFs
_Gs = whv.WHvX64RegisterGs
_Ldtr = whv.WHvX64RegisterLdtr
_Tr = whv.WHvX64RegisterTr

# X64 Table registers
_Idtr = whv.WHvX64RegisterIdtr
_Gdtr = whv.WHvX64RegisterGdtr

# X64 Control Registers
_Cr0 = whv.WHvX64RegisterCr0
_Cr2 = whv.WHvX64RegisterCr2
_Cr3 = whv.WHvX64RegisterCr3
_Cr4 = whv.WHvX64RegisterCr4
_Cr8 = whv.WHvX64RegisterCr8

# X64 Debug Registers
_Dr0 = whv.WHvX64RegisterDr0
_Dr1 = whv.WHvX64RegisterDr1
_Dr2 = whv.WHvX64RegisterDr2
_Dr3 = whv.WHvX64RegisterDr3
_Dr6 = whv.WHvX64RegisterDr6
_Dr7 = whv.WHvX64RegisterDr7

# X64 Extended Control Registers
_XCr0 = whv.WHvX64RegisterXCr0

# X64 Floating Point and Vector Registers
_Xmm0 = whv.WHvX64RegisterXmm0
_Xmm1 = whv.WHvX64RegisterXmm1
_Xmm2 = whv.WHvX64RegisterXmm2
_Xmm3 = whv.WHvX64RegisterXmm3
_Xmm4 = whv.WHvX64RegisterXmm4
_Xmm5 = whv.WHvX64RegisterXmm5
_Xmm6 = whv.WHvX64RegisterXmm6
_Xmm7 = whv.WHvX64RegisterXmm7
_Xmm8 = whv.WHvX64RegisterXmm8
_Xmm9 = whv.WHvX64RegisterXmm9
_Xmm10 = whv.WHvX64RegisterXmm10
_Xmm11 = whv.WHvX64RegisterXmm11
_Xmm12 = whv.WHvX64RegisterXmm12
_Xmm13 = whv.WHvX64RegisterXmm13
_Xmm14 = whv.WHvX64RegisterXmm14
_Xmm15 = whv.WHvX64RegisterXmm15
_FpMmx0 = whv.WHvX64RegisterFpMmx0
_FpMmx1 = whv.WHvX64RegisterFpMmx1
_FpMmx2 = whv.WHvX64RegisterFpMmx2
_FpMmx3 = whv.WHvX64RegisterFpMmx3
_FpMmx4 = whv.WHvX64RegisterFpMmx4
_FpMmx5 = whv.WHvX64RegisterFpMmx5
_FpMmx6 = whv.WHvX64RegisterFpMmx6
_FpMmx7 = whv.WHvX64RegisterFpMmx7
_FpControlStatus = whv.WHvX64RegisterFpControlStatus
_XmmControlStatus = whv.WHvX64RegisterXmmControlStatus

# X64 MSRs
_Tsc = whv.WHvX64RegisterTsc
_Efer = whv.WHvX64RegisterEfer
_KernelGsBase = whv.WHvX64RegisterKernelGsBase
_ApicBase = whv.WHvX64RegisterApicBase
_Pat = whv.WHvX64RegisterPat
_SysenterCs = whv.WHvX64RegisterSysenterCs
_SysenterEip = whv.WHvX64RegisterSysenterEip
_SysenterEsp = whv.WHvX64RegisterSysenterEsp
_Star = whv.WHvX64RegisterStar
_Lstar = whv.WHvX64RegisterLstar
_Cstar = whv.WHvX64RegisterCstar
_Sfmask = whv.WHvX64RegisterSfmask

_MsrMtrrCap = whv.WHvX64RegisterMsrMtrrCap
_MsrMtrrDefType = whv.WHvX64RegisterMsrMtrrDefType

_MsrMtrrPhysBase0 = whv.WHvX64RegisterMsrMtrrPhysBase0
_MsrMtrrPhysBase1 = whv.WHvX64RegisterMsrMtrrPhysBase1
_MsrMtrrPhysBase2 = whv.WHvX64RegisterMsrMtrrPhysBase2
_MsrMtrrPhysBase3 = whv.WHvX64RegisterMsrMtrrPhysBase3
_MsrMtrrPhysBase4 = whv.WHvX64RegisterMsrMtrrPhysBase4
_MsrMtrrPhysBase5 = whv.WHvX64RegisterMsrMtrrPhysBase5
_MsrMtrrPhysBase6 = whv.WHvX64RegisterMsrMtrrPhysBase6
_MsrMtrrPhysBase7 = whv.WHvX64RegisterMsrMtrrPhysBase7
_MsrMtrrPhysBase8 = whv.WHvX64RegisterMsrMtrrPhysBase8
_MsrMtrrPhysBase9 = whv.WHvX64RegisterMsrMtrrPhysBase9
_MsrMtrrPhysBaseA = whv.WHvX64RegisterMsrMtrrPhysBaseA
_MsrMtrrPhysBaseB = whv.WHvX64RegisterMsrMtrrPhysBaseB
_MsrMtrrPhysBaseC = whv.WHvX64RegisterMsrMtrrPhysBaseC
_MsrMtrrPhysBaseD = whv.WHvX64RegisterMsrMtrrPhysBaseD
_MsrMtrrPhysBaseE = whv.WHvX64RegisterMsrMtrrPhysBaseE
_MsrMtrrPhysBaseF = whv.WHvX64RegisterMsrMtrrPhysBaseF

_MsrMtrrPhysMask0 = whv.WHvX64RegisterMsrMtrrPhysMask0
_MsrMtrrPhysMask1 = whv.WHvX64RegisterMsrMtrrPhysMask1
_MsrMtrrPhysMask2 = whv.WHvX64RegisterMsrMtrrPhysMask2
_MsrMtrrPhysMask3 = whv.WHvX64RegisterMsrMtrrPhysMask3
_MsrMtrrPhysMask4 = whv.WHvX64RegisterMsrMtrrPhysMask4
_MsrMtrrPhysMask5 = whv.WHvX64RegisterMsrMtrrPhysMask5
_MsrMtrrPhysMask6 = whv.WHvX64RegisterMsrMtrrPhysMask6
_MsrMtrrPhysMask7 = whv.WHvX64RegisterMsrMtrrPhysMask7
_MsrMtrrPhysMask8 = whv.WHvX64RegisterMsrMtrrPhysMask8
_MsrMtrrPhysMask9 = whv.WHvX64RegisterMsrMtrrPhysMask9
_MsrMtrrPhysMaskA = whv.WHvX64RegisterMsrMtrrPhysMaskA
_MsrMtrrPhysMaskB = whv.WHvX64RegisterMsrMtrrPhysMaskB
_MsrMtrrPhysMaskC = whv.WHvX64RegisterMsrMtrrPhysMaskC
_MsrMtrrPhysMaskD = whv.WHvX64RegisterMsrMtrrPhysMaskD
_MsrMtrrPhysMaskE = whv.WHvX64RegisterMsrMtrrPhysMaskE
_MsrMtrrPhysMaskF = whv.WHvX64RegisterMsrMtrrPhysMaskF

_MsrMtrrFix64k00000 = whv.WHvX64RegisterMsrMtrrFix64k00000
_MsrMtrrFix16k80000 = whv.WHvX64RegisterMsrMtrrFix16k80000
_MsrMtrrFix16kA0000 = whv.WHvX64RegisterMsrMtrrFix16kA0000
_MsrMtrrFix4kC0000 = whv.WHvX64RegisterMsrMtrrFix4kC0000
_MsrMtrrFix4kC8000 = whv.WHvX64RegisterMsrMtrrFix4kC8000
_MsrMtrrFix4kD0000 = whv.WHvX64RegisterMsrMtrrFix4kD0000
_MsrMtrrFix4kD8000 = whv.WHvX64RegisterMsrMtrrFix4kD8000
_MsrMtrrFix4kE0000 = whv.WHvX64RegisterMsrMtrrFix4kE0000
_MsrMtrrFix4kE8000 = whv.WHvX64RegisterMsrMtrrFix4kE8000
_MsrMtrrFix4kF0000 = whv.WHvX64RegisterMsrMtrrFix4kF0000
_MsrMtrrFix4kF8000 = whv.WHvX64RegisterMsrMtrrFix4kF8000

_TscAux = whv.WHvX64RegisterTscAux
_SpecCtrl = whv.WHvX64RegisterSpecCtrl
_PredCmd = whv.WHvX64RegisterPredCmd

# APIC state (also accessible via WHv(Get/Set)VirtualProcessorInterruptControllerState)
_ApicId = whv.WHvX64RegisterApicId
_ApicVersion = whv.WHvX64RegisterApicVersion

# Interrupt / Event Registers
_RegisterPendingInterruption = whv.WHvRegisterPendingInterruption
_RegisterInterruptState = whv.WHvRegisterInterruptState
_RegisterPendingEvent = whv.WHvRegisterPendingEvent
_DeliverabilityNotifications = whv.WHvX64RegisterDeliverabilityNotifications
_RegisterInternalActivityState = whv.WHvRegisterInternalActivityState

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04

def Align2Page(Size):
    '''Align the size to the next page size'''
    if (Size % 0x1000) == 0:
        return Size
    return ((Size / 0x1000) + 1) * 0x1000

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

def IsHypervisorPresent():
    '''Is the support for the Hypervisor Platform APIs
    enabled?'''
    Capabilities = whv.WHV_CAPABILITY()
    Success, _, _ = WHvGetCapability(
        whv.WHvCapabilityCodeHypervisorPresent,
        Capabilities
    )

    return Success and Capabilities.HypervisorPresent == 1

class WHvPartition(object):
    '''Context manager for Partition.'''
    def __init__(self, **kwargs):
        '''Create and setup a Partition object.'''
        assert IsHypervisorPresent(), 'The hypervisor platform APIs support must be turned on.'
        self.CurrentGpa = 0
        self.ProcessorCount = kwargs.get('ProcessorCount', 1)
        self.Name = kwargs.get('Name', 'DefaultName')
        self.ExceptionExitBitmap = kwargs.get('ExceptionExitBitmap', 0)
        self.TranslationTable = {}

        # Create the partition.
        Success, Partition, Ret = WHvCreatePartition()
        assert Success, 'WHvCreatePartition failed in context manager with %x.' % Ret
        self.Partition = Partition

        # Set-up the partition with a number of VPs.
        Property = whv.WHV_PARTITION_PROPERTY()
        Property.ProcessorCount = self.ProcessorCount
        Success, Ret = WHvSetPartitionProperty(
            self.Partition,
            whv.WHvPartitionPropertyCodeProcessorCount,
            Property
        )
        assert Success, 'WHvSetPartitionProperty(ProcessorCount) failed in context manager with %x.' % Ret

        # Activate the partition.
        Success, Ret = WHvSetupPartition(self.Partition)
        assert Success, 'WHvSetupPartition failed in context manager with %x.' % Ret

        # Create the virtual processors.
        for VpIndex in range(self.ProcessorCount):
            Success, Ret = WHvCreateVirtualProcessor(
                self.Partition,
                VpIndex
            )
            assert Success, 'WHvCreateVirtualProcessor(%d) failed in context manager with %x.' % (VpIndex, Ret)

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        BlockHasThrown = etype is not None

        # Release the VPs.
        for VpIndex in range(self.ProcessorCount):
            Success, Ret = WHvDeleteVirtualProcessor(
                self.Partition,
                VpIndex
            )
            assert Success, 'WHvDeleteVirtualProcessor failed in context manager with %x.' % Ret

        # Release the Partition.
        Success, Ret = WHvDeletePartition(self.Partition)
        assert Success, 'WHvDeletePartition failed in context manager with %x.' % Ret

        # Forward the exception is we've intercepted one, otherwise s'all good.
        return not BlockHasThrown

    def __repr__(self):
        return 'Partition(%r, ProcessorCount=%d)' % (
            self.Name,
            self.ProcessorCount
        )

    def RunVp(self, VpIndex):
        '''Run the virtual processor.'''
        Success, ExitContext, Ret = WHvRunVirtualProcessor(
            self.Partition, VpIndex
        )

        assert Success, ('WHvRunVirtualProcessor failed with %x.' % Ret)

        return ExitContext

    def SetRegisters(self, VpIndex, Registers):
        '''Set registers in a VP.'''
        Success, Ret = WHvSetVirtualProcessorRegisters(
            self.Partition,
            VpIndex,
            Registers
        )

        assert Success, 'WHvSetVirtualProcessorRegisters failed with %x.' % Ret

    def SetRip(self, VpIndex, Rip):
        '''Set the @rip register of a VP'''
        return self.SetRegisters(
            VpIndex, {
                _Rip: Rip
            }
        )

    def GetRegisters(self, VpIndex, Registers, Reg64 = False):
        '''Get registers of a VP.'''
        Success, Registers, Ret = WHvGetVirtualProcessorRegisters(
            self.Partition,
            VpIndex,
            Registers
        )

        assert Success, 'GetRegisters failed with %x.' % Ret
        if Reg64:
            Registers = map(
                lambda R: R.Reg64,
                Registers
            )

        return Registers

    def GetRegisters64(self, VpIndex, Registers):
        '''Get registers of a VP and return the .Reg64 part.'''
        return self.GetRegisters(VpIndex, Registers, Reg64 = True)

    def GetRegister(self, VpIndex, Register):
        return self.GetRegisters(
            VpIndex,
            (Register, )
        )[0]

    def GetRip(self, VpIndex):
        '''Get the @rip register of a VP.'''
        return self.GetRegisters64(
            VpIndex,
            (_Rip, )
        )[0]

    def DumpRegisters(self, VpIndex):
        '''Dump the register of a VP.'''
        R = self.GetRegisters(
            VpIndex, [
                _Rax, _Rbx, _Rcx, _Rdx, _Rsi, _Rdi,
                _Rip, _Rsp, _Rbp, _R8, _R9, _R10,
                _R11, _R12, _R13, _R14, _R15,
                _Cs, _Ss, _Ds, _Es, _Fs, _Gs,
                _Rflags, _Cr3
            ]
        )

        print 'rax=%016x rbx=%016x rcx=%016x' % (
            R[0].Reg64, R[1].Reg64, R[2].Reg64
        )

        print 'rdx=%016x rsi=%016x rdi=%016x' % (
            R[3].Reg64, R[4].Reg64, R[5].Reg64
        )

        print 'rip=%016x rsp=%016x rbp=%016x' % (
            R[6].Reg64, R[7].Reg64, R[8].Reg64
        )

        print ' r8=%016x  r9=%016x r10=%016x' % (
            R[9].Reg64, R[10].Reg64, R[11].Reg64
        )

        print 'r11=%016x r12=%016x r13=%016x' % (
            R[12].Reg64, R[13].Reg64, R[14].Reg64
        )

        print 'r14=%016x r15=%016x' % (
            R[15].Reg64, R[16].Reg64
        )

        Rflags = R[23].Reg64
        print 'iopl=%x %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s' % (
            (Rflags >> 12) & 3,
            'cs' if ((Rflags >> 0x00) & 1) else '   ',
            'pf' if ((Rflags >> 0x02) & 1) else '   ',
            'af' if ((Rflags >> 0x04) & 1) else '   ',
            'zf' if ((Rflags >> 0x06) & 1) else '   ',
            'sf' if ((Rflags >> 0x07) & 1) else '   ',
            'tf' if ((Rflags >> 0x08) & 1) else '   ',
            'if' if ((Rflags >> 0x09) & 1) else '   ',
            'df' if ((Rflags >> 0x0a) & 1) else '   ',
            'of' if ((Rflags >> 0x0b) & 1) else '   ',
            'nt' if ((Rflags >> 0x0e) & 1) else '   ',
            'rf' if ((Rflags >> 0x10) & 1) else '   ',
            'vm' if ((Rflags >> 0x11) & 1) else '   ',
            'ac' if ((Rflags >> 0x12) & 1) else '   ',
            'vif' if ((Rflags >> 0x13) & 1) else '    ',
            'vip' if ((Rflags >> 0x14) & 1) else '    ',
            'id' if ((Rflags >> 0x15) & 1) else '   ',
        )

        print 'cs=%04x ss=%04x ds=%04x es=%04x fs=%04x gs=%04x efl=%08x cr3=%08x' % (
            R[17].Segment.Selector,
            R[18].Segment.Selector,
            R[19].Segment.Selector,
            R[20].Segment.Selector,
            R[21].Segment.Selector,
            R[22].Segment.Selector,
            Rflags,
            R[24].Reg64
        )

    def MapGpaRangeWithoutContent(self, SizeInBytes, Gpa, Flags):
        SizeInBytes = Align2Page(SizeInBytes)
        Hva = VirtualAlloc(
            0,
            SizeInBytes,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )

        assert Hva is not None, 'VirtualAlloc failed.'

        Success, Ret = WHvMapGpaRange(
            self.Partition,
            Hva,
            Gpa,
            SizeInBytes,
            Flags
        )

        assert Success, 'WHvMapGpaRange failed with %x.' % Ret
        self.TranslationTable[Gpa] = Hva
        return (Hva, Gpa, SizeInBytes)

    def MapGpaRange(self, Buffer, Gpa, Flags):
        '''Map physical memory into the partition backed by process virtual-memory.'''
        Hva, _, SizeInBytes = self.MapGpaRangeWithoutContent(
            len(Buffer),
            Gpa,
            Flags
        )

        ct.memmove(Hva, Buffer, len(Buffer))
        return (SourceBuffer, SizeInBytes)

    def MapCode(self, Code, Gpa, Writeable = False):
        '''Map code into the partition.'''
        Flags = 'rx'

        if Writeable:
            Flags += 'w'

        HostAddress, CodeLength = self.MapGpaRange(
            Code,
            Gpa,
            'rx'
        )

        return (HostAddress, CodeLength)

    def GetGpa(self):
        Gpa = self.CurrentGpa
        self.CurrentGpa += 0x1000
        return Gpa

    def TranslateGva(self, VpIndex, Gva, Flags = None):
        if Flags is None:
            Flags = whv.WHvTranslateGvaFlagValidateRead | whv.WHvTranslateGvaFlagPrivilegeExempt

        Success, ResultCode, Gpa, Ret = WHvTranslateGva(
            self.Partition,
            VpIndex,
            Gva,
            Flags
        )

        assert Success, 'WHvTranslateGva failed with: %x.' % Ret
        return (WHvTranslateGvaResultCode(ResultCode), Gpa)

def Generate32bCodeSegment():
    '''Generate a 32-bit code ring0'''
    CsSegment = whv.WHV_REGISTER_VALUE()
    CsSegment.Segment.Base = 0x0
    CsSegment.Segment.Limit = 0xffffffff
    CsSegment.Segment.Selector = 0x1337
    # A=Accessed, R=Readabale, C=Conforming, Reserved.
    CsSegment.Segment.SegmentType = 0b1011
    # bit12
    CsSegment.Segment.NonSystemSegment = 1
    CsSegment.Segment.DescriptorPrivilegeLevel = 0
    # P=Present.
    CsSegment.Segment.Present = 1
    # AVL=Available.
    CsSegment.Segment.Available = 0
    # L=Long-mode segment
    CsSegment.Segment.Long = 0
    # D=Default operand size.
    CsSegment.Segment.Default = 1
    # G=Granularity.
    CsSegment.Segment.Granularity = 1
    return CsSegment

def Config32bEnvironment(Partition):
    '''XXX: remove this'''
    pass

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

def DumpSegment(Segment):
    '''Dump a segment on stdout.'''
    S = Segment
    print '                    Base:', hex(S.Base)
    print '                   Limit:', hex(S.Limit)
    print '                Selector:', hex(S.Selector)
    print '             SegmentType:', hex(S.SegmentType)
    print '        NonSystemSegment:', hex(S.NonSystemSegment)
    print 'DescriptorPrivilegeLevel:', hex(S.DescriptorPrivilegeLevel)
    print '                 Present:', hex(S.Present)
    print '                     AVL:', hex(S.Available)
    print '                    Long:', hex(S.Long)
    print '                 Default:', hex(S.Default)
    print '             Granularity:', hex(S.Granularity)

def DumpExitContext(ExitContext):
    '''Dump a WHV_RUN_VP_EXIT_CONTEXT on stdout.'''
    E = ExitContext
    print 'ExitReason:', WHvExitReason(E.ExitReason)
    V = E.VpContext
    print 'VpContext.InstructionLength:', hex(V.InstructionLength)
    print 'VpContext.Cr8:', hex(V.Cr8)
    print 'VpContext.Cs:', hex(V.Cs.Selector)
    print 'VpContext.Rip:', hex(V.Rip)
    print 'VpContext.Rflags:', hex(V.Rflags)
    if E.ExitReason == whv.WHvRunVpExitReasonMemoryAccess:
        M = E.MemoryAccess
        print 'MemoryAccess.InstructionByteCount:', hex(M.InstructionByteCount)
        A = M.AccessInfo
        print 'MemoryAccess.AccessInfo.AccessType:', hex(A.AccessType)
        print 'MemoryAccess.AccessInfo.GpaUnmapped:', hex(A.GpaUnmapped)
        print 'MemoryAccess.AccessInfo.GvaValid:', hex(A.GvaValid)
        print 'MemoryAccess.Gpa:', hex(M.Gpa)
        print 'MemoryAccess.Gva:', hex(M.Gva)

def CR0(Cr0):
    '''Return a string representation of CR0.'''
    C = Cr0.Reg64
    Bits = {
        0 : 'PE',
        1 : 'MP',
        2 : 'EM',
        3 : 'TS',
        4 : 'ET',
        5 : 'NE',
        16 : 'WP',
        18 : 'AM',
        29 : 'NW',
        30 : 'CD',
        31 : 'PG'
    }
    S = []
    for Bit, Str in Bits.iteritems():
        if (C >> Bit) & 1:
            S.append('CR0.%s' % Str)
    S.append('(%08x)' % C)
    return ' '.join(S)

def CR4(Cr4):
    '''Return a string representation of CR4.'''
    C = Cr4.Reg64
    Bits = {
        0 : 'VME',
        1 : 'PVI',
        2 : 'TSD',
        3 : 'DE',
        4 : 'PSE',
        5 : 'PAE',
        6 : 'MCE',
        7 : 'PGE',
        8 : 'PCE',
        9 : 'OSFXSR',
        10 : 'OSXMMEXCPT',
        11 : 'UMIP',
        12 : 'LA57',
        13 : 'VMXE',
        14 : 'SMXE',
        16 : 'FSGSBASE',
        17 : 'PCIDE',
        18 : 'OSXSAVE',
        20 : 'SMEP',
        21 : 'SMAP',
        22 : 'PKE'
    }
    S = []
    for Bit, Str in Bits.iteritems():
        if (C >> Bit) & 1:
            S.append('CR4.%s' % Str)
    S.append('(%08x)' % C)
    return ' '.join(S)


def BuildVirtualAddressSpace(Partition, PageGvas):
    '''This function builds the proper paging structures necessary
    to back a set of GVAs pages.

    Little 'how to 4-level paging':

        * PML4->PDPT->PD->PT,
        * Each entry are 8 bytes long,
        * The virtual-address is broken down like this:
            [Unused - 16 bits][PML4 Index - 9 bits][PDPT Index - 9 bits][PD Index - 9 bits][PT Index - 9 bits][Page Offset 12 bits]
    '''

    PageTables = []

    # Walk the GVA and keep track of the various paging structures
    # we need.
    for PageGva in PageGvas:
        PtIndex   = (PageGva >> (12 + (9 * 0))) & 0b111111111
        PdIndex   = (PageGva >> (12 + (9 * 1))) & 0b111111111
        PdptIndex = (PageGva >> (12 + (9 * 2))) & 0b111111111
        Pml4Index = (PageGva >> (12 + (9 * 3))) & 0b111111111
        PageTables.append((
            PageGva,
            PtIndex,
            PdIndex,
            PdptIndex,
            Pml4Index
        ))

    from pprint import pprint
    pprint(PageTables)

    # Those keep track of the various paging structure we have already allocated.
    GvaEntries = {}
    PtEntries = {}
    PdEntries = {}
    PdptEntries = {}
    Pml4Entries = {}

    def AllocateTableIfNeeded(Ledger, Idx, Flags = 'rw'):
        PageInfo = Ledger.get(Idx, None)
        if PageInfo is not None:
            return PageInfo

        # Allocate backing memory host side.
        Hva, Gpa, _ = Partition.MapGpaRangeWithoutContent(
            0x1000,
            Partition.GetGpa(),
            Flags
        )

        # Feed the information into the appropriate ledger. We keep track
        # of the host address and the GPA.
        Ledger[Idx] = (Hva, Gpa)
        return (Hva, Gpa)

    # We know we need a PML4 table, so allocate it now.
    Pml4Hva, Pml4Gpa, _ = Partition.MapGpaRangeWithoutContent(
        0x1000,
        Partition.GetGpa(),
        'rw'
    )

    GetPfn = lambda A: A / 0x1000

    for Gva, PtIdx, PdIdx, PdptIdx, Pml4Idx in PageTables:
        # Allocate a page for each level if needed.
        GvaHva, GvaGpa = AllocateTableIfNeeded(PtEntries, PtIdx, 'rwx')
        PtHva, PtGpa = AllocateTableIfNeeded(PdEntries, PdIdx)
        PdHva, PdGpa = AllocateTableIfNeeded(PdptEntries, PdptIdx)
        PdptHva, PdptGpa = AllocateTableIfNeeded(Pml4Entries, Pml4Idx)
        Pml4Entries.setdefault(Pml4Idx, (Pml4Hva, Pml4Gpa))

        # XXX: remove this when i can find the hpa outside.
        code = '\x48\xff\xc0'*137 + '\xcc'
        ct.memmove(GvaHva, code, len(code))

        print 'Pml4Hva', hex(Pml4Hva), 'Pml4Gpa', hex(Pml4Gpa), 'Pfn', GetPfn(Pml4Gpa), 'Pml4e', 255
        print 'PdptHva', hex(PdptHva), 'PdptGpa', hex(PdptGpa), 'Pfn', GetPfn(PdptGpa), 'Pdpte', PdptIdx
        print '  PdHva', hex(PdHva), '  PdGpa', hex(PdGpa), 'Pfn', GetPfn(PdGpa),'  Pde', PdIdx
        print '  PtHva', hex(PtHva), '  PtGpa', hex(PtGpa), 'Pfn', GetPfn(PtGpa), '  Pte', PtIdx
        print 'PageHva', hex(GvaHva), 'PageGpa', hex(GvaGpa), 'Pfn', GetPfn(GvaGpa)

        # Now that we have the memory backing the various levels
        # we want to properly link them together.
        TableEntry = whv.MMPTE_HARDWARE()
        TableEntry.AsUINT64 = 0
        TableEntry.Present = 1
        TableEntry.Write = 1
        TableEntry.UserAccessible = 1

        # First, the PML4E to the PDPT.
        TableEntry.PageFrameNumber = GetPfn(PdptGpa)
        Pml4 = (SIZE_T * 512).from_address(Pml4Hva)
        Pml4[Pml4Idx] = TableEntry.AsUINT64

        # Next, the PDPTE to the PD.
        TableEntry.PageFrameNumber = GetPfn(PdGpa)
        Pdpt = (SIZE_T * 512).from_address(PdptHva)
        Pdpt[PdptIdx] = TableEntry.AsUINT64

        # Next, the PDE to the PT.
        TableEntry.PageFrameNumber = GetPfn(PtGpa)
        Pd = (SIZE_T * 512).from_address(PdHva)
        Pd[PdIdx] = TableEntry.AsUINT64

        # Finally, the PTE to the Page.
        TableEntry.PageFrameNumber = GetPfn(GvaGpa)
        Pt = (SIZE_T * 512).from_address(PtHva)
        Pt[PtIdx] = TableEntry.AsUINT64

    print Pml4Entries, PdptEntries
    PageCount = len(GvaEntries) + len(PtEntries) + len(PdEntries) + len(PdptEntries) + len(Pml4Entries) + 1
    print 'This VA requires', PageCount, 'pages total which is', (PageCount * 0x1000) / 1024 / 1024, 'MB'
    return Pml4Gpa

def main(argc, argv):
    HypervisorPresent = IsHypervisorPresent()
    print 'HypervisorPresent:', HypervisorPresent
    if not HypervisorPresent:
        return 1

    StructSizes = {
        whv.WHV_RUN_VP_EXIT_CONTEXT : 144,
        whv.WHV_CAPABILITY : 8,
        whv.WHV_PARTITION_PROPERTY : 32,
        whv.WHV_REGISTER_VALUE : 16
    }

    for Struct, StructSize in StructSizes.iteritems():
        Success = len(Struct()) == StructSize
        print 'sizeof(%s) == %d: %r' % (Struct.__name__, StructSize, Success)
        if not Success:
            return 1

    print '64-bit kernel'.center(80, '=')

    PartitionOptions = {
       'ProcessorCount' : 1,
       'Name' : '64b user'
    }


    with WHvPartition(**PartitionOptions) as Partition:
        print 'Partition created:', Partition

        # Configure the base of the IDT where we don't have any memory mapped.
        # This allow us to trigger a memory access violation when it is read.
        IdtGpa = Partition.GetGpa()
        Idtr = whv.WHV_REGISTER_VALUE()
        Idtr.Table.Base = IdtGpa
        Idtr.Table.Limit = 0

        # Let's enable long mode now...
        # https://wiki.osdev.org/Setting_Up_Long_Mode.
        # We basically need several things (cf https://wiki.osdev.org/X86-64):
        #   * Set the PAE enable bit in CR4
        #   * Load CR3 with the physical address of the PML4
        #   * Enable long mode by setting the EFER.LME flag in MSR 0xC0000080
        #   * Enable paging

        # Little remainder how this shit works: PML4->PDPT->PD->PT (aka 4 level paging).
        # Each entry are 8 bytes long, and each table have 512 entries.
        # This allow us to address at most: (4096 * PAGE_SIZE) * 4096 * 4096 * 4096
        # PML4 physical address.
        #
        # OK so we need to allocate memory for paging structures, and build the
        # virtual address space.
        Pages = [
            0x0007fffb8c05000,
            0x0007fffb8c06000,
            0x0007fffb8c07000,
            0x0007ff746a40000
        ]

        PagingBase = Partition.GetGpa()
        Pml4Gpa = BuildVirtualAddressSpace(
            Partition,
            Pages
        )

        # Turn on CR4.PAE.
        # kd> r @cr4
        # cr4=0000000000170678
        # 0b100110000011000100000
        # 'Physical Address Extension', 'Operating system support for FXSAVE and FXRSTOR instructions',
        # 'Operating System Support for Unmasked SIMD Floating-Point Exceptions',
        # 'Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE',
        # 'PCID Enable', 'Supervisor Mode Execution Protection Enable'.
        Cr4 = 0x000000000170678

        # We need to update CR3 to point to the PML4's physical address.
        Cr3 = Pml4Gpa

        # Turn on EFER.LME.
        # kd> rdmsr 0xC0000080
        # msr[c0000080] = 00000000`00000d01
        # 0b0000110100000001
        # 'System Call Extensions', 'Long Mode Enable', 'Long Mode Active', 'No-Execute Enable'.
        Efer = 0xD01

        # Turn on CR0.PG.
        # kd> r @cr0
        # Last set context:
        # cr0=0000000080050031
        # 'Protected Mode Enable', 'Extension type', 'Numeric Error', 'Write Protect',
        # 'Alignment mask', 'Paging'.
        Cr0 = 0x80050031
        Partition.SetRegisters(
            0, {
                _Idtr : Idtr,
                _Cr0 : Cr0,
                _Cr3 : Cr3,
                _Cr4 : Cr4,
                _Efer : Efer
            }
        )

        print 'Enabled 64-bit long mode'

        # We should be good to set-up 64-bit user-mode segments now.
        # 0:000> r @cs
        # cs=0033
        Cs = whv.WHV_REGISTER_VALUE()
        Cs.Segment.Base = 0x0
        Cs.Segment.Limit = 0xffffffff
        Cs.Segment.Selector = 0x33
        # XXX: Correct this, A=Accessed, R=Readabale, C=Conforming, Reserved.
        Cs.Segment.SegmentType = 0b1011
        # bit12
        Cs.Segment.NonSystemSegment = 1
        Cs.Segment.DescriptorPrivilegeLevel = 3
        # P=Present.
        Cs.Segment.Present = 1
        # AVL=Available.
        Cs.Segment.Available = 0
        # L=Long-mode segment
        Cs.Segment.Long = 1
        # D=Default operand size.
        Cs.Segment.Default = 0
        # G=Granularity.
        Cs.Segment.Granularity = 1

        # 0:001> r @ss
        # ss=002b
        # 0:001> r @fs
        # fs=0053
        Ss = whv.WHV_REGISTER_VALUE()
        Ss.Segment.Base = 0x0
        Ss.Segment.Limit = 0xffffffff
        Ss.Segment.Selector = 0x2b
        # XXX: Correct this, A=Accessed, R=Readabale, C=Conforming, Reserved.
        Ss.Segment.SegmentType = 0b0011
        # bit12
        Ss.Segment.NonSystemSegment = 1
        Ss.Segment.DescriptorPrivilegeLevel = 3
        # P=Present.
        Ss.Segment.Present = 1
        # AVL=Available.
        Ss.Segment.Available = 0
        # L=Long-mode segment
        Ss.Segment.Long = 1
        # D=Default operand size.
        Ss.Segment.Default = 0
        # G=Granularity.
        Ss.Segment.Granularity = 1

        # XXX: Configure GS.
        Partition.SetRegisters(
            0, {
                _Cs : Cs,
                _Ss : Ss,
                _Ds : Ss,
                _Es : Ss,
                _Fs : Ss,
                _Gs : Ss,
                _Rdx : 0,
                _Rflags : 0x202
            }
        )

        # Let's start to map code/data from this address
        #CodeGva = Pages[0]
        #Partition.MapCode(
        #    '\x48\xff\xc0' * 1337,
        #    USER_GPA
        #)

        Partition.SetRip(
            0,
            Pages[0]
        )

        for Gva in Pages:
            ResultCode, Gpa = Partition.TranslateGva(
                0,
                Gva
            )
            print 'Gva: %016x to Gpa %016x' % (Gva, Gpa)
            assert ResultCode.value == whv.WHvTranslateGvaResultSuccess, 'TranslateGva(%x) returned %s.' % (Gpa, ResultCode)

        print 'GVA->GPA translations worked!'
        ExitContext = Partition.RunVp(0)
        Partition.DumpRegisters(0)

        ExitReason = WHvExitReason(ExitContext.ExitReason)
        print 'Partition exited with:', ExitReason
        DumpExitContext(ExitContext)
        Rip, Rax = Partition.GetRegisters64(
            0, (
                _Rip,
                _Rax
            )
        )

        assert Rax == 137, '@rax(%x) does not match the magic value.' % Rax
        assert Rip == (Pages[0] + (137 * 3)), '@rip(%x) does not match the end @rip.' % Rip
        # XXX: We want an actual memory violation when reading IDT.
        assert ExitReason.value == whv.WHvRunVpExitReasonUnrecoverableException, 'A memory fault is expected when the int3 is triggered as the IDTR.Base is unmapped.'

    return
    print '32-bit kernel'.center(80, '=')
    IDT_GPA = 0xffff0000
    CODE_GPA = 0x0

    PartitionOptions = {
        'ProcessorCount' : 1,
        'Name' : '32b kernel'
    }

    with WHvPartition(**PartitionOptions) as Partition:
        print 'Partition created:', Partition

        InitialRip = Partition.GetRip(0)
        assert InitialRip == 0xfff0, 'The initial @rip(%x) does not match with expected value.' % InitialRip
        print 'Initial @rip in VP0:', hex(InitialRip)

        GuestCodePageAddress, _ = Partition.MapCode(
            # inc eax ; ... ; int3
            '\x40' * 0x1337 + '\xcc',
            CODE_GPA
        )

        print 'Mapped GPA:%x backed by memory at %016x' % (
            CODE_GPA,
            GuestCodePageAddress
        )

        Cr0, Gdtr, Idtr = Partition.GetRegisters(0, (
                _Cr0,
                _Gdtr,
                _Idtr
            )
        )

        print 'CR0:', CR0(Cr0)
        print 'GDTR.Base:', hex(Gdtr.Table.Base)
        print 'GDTR.Limit:', hex(Gdtr.Table.Limit)
        print 'IDTR.Base:', hex(Idtr.Table.Base)
        print 'IDTR.Limit:', hex(Idtr.Table.Limit)
        Idtr.Table.Base = IDT_GPA

        Partition.SetRegisters(
            0, {
                _Rip : CODE_GPA,
                _Cs : Generate32bCodeSegment(),
                _Idtr : Idtr,
                #_Cr0 : Cr0.Reg64 | 1
            }
        )
        print 'Partition configured to run 32b kernel code'

        Rip = Partition.GetRip(0)
        print '@rip in VP0:', hex(Rip)
        assert Rip == CODE_GPA, '@rip(%x) does not match what we assigned to it.' % Rip

        ExitContext = Partition.RunVp(0)
        ExitReason = WHvExitReason(ExitContext.ExitReason)
        print 'Partition exited with:', ExitReason
        DumpExitContext(ExitContext)

        Partition.DumpRegisters(0)
        Rip, Rax = Partition.GetRegisters64(
            0, (
                _Rip,
                _Rax
            )
        )

        assert Rip == (CODE_GPA + 0x1337), '@rax(%x) does not match the magic value.' % Rax
        assert ExitReason.value == whv.WHvRunVpExitReasonMemoryAccess, 'A memory fault is expected when the int3 is triggered as the IDTR.Base is unmapped.'
        FaultGpa = ExitContext.MemoryAccess.Gpa
        InterruptionPending = ExitContext.VpContext.ExecutionState.InterruptionPending
        InIdtBound = FaultGpa > IDT_GPA and FaultGpa < (IDT_GPA + Idtr.Table.Limit)
        assert InterruptionPending and InIdtBound, 'The GPA faulting must be in the bound of the IDT.'

    print 'All good!'
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
