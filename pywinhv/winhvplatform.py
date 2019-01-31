# Axel '0vercl0k' Souchet - 23 January 2019
import pywinhv as whv
import ctypes as ct
from ctypes.wintypes import LPVOID, DWORD, c_size_t as SIZE_T
import sys
from enum import Enum

ct.windll.kernel32.VirtualAlloc.argtypes = (LPVOID, SIZE_T, DWORD, DWORD)
ct.windll.kernel32.VirtualAlloc.restype = LPVOID
VirtualAlloc = ct.windll.kernel32.VirtualAlloc

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
        self.ProcessorCount = kwargs.get('ProcessorCount', 1)
        self.Name = kwargs.get('Name', 'DefaultName')
        self.ExceptionExitBitmap = kwargs.get('ExceptionExitBitmap', 0)

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

        # Enable Exception vmexits.
        #Property.ExtendedVmExits.ExceptionExit = 1
        #Success, Ret = WHvSetPartitionProperty(
        #    self.Partition,
        #    whv.WHvPartitionPropertyCodeExtendedVmExits,
        #    Property
        #)
        #assert Success, 'WHvSetPartitionProperty(ExtendedVmExits) failed in context manager with %x.' % Ret

        ## Configure the ExceptionExitBitmap
        #Property.ExceptionExitBitmap = self.ExceptionExitBitmap
        #Success, Ret = WHvSetPartitionProperty(
        #    self.Partition,
        #    whv.WHvPartitionPropertyCodeExceptionExitBitmap,
        #    Property
        #)
        #assert Success, 'WHvSetPartitionProperty(ExitBitmap) failed in context manager with %x.' % Ret

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

        if not Success:
            raise RuntimeError('WHvRunVirtualProcessor failed with %x.' % Ret)

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
                whv.WHvX64RegisterRip: Rip
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

    def GetRip(self, VpIndex):
        '''Get the @rip register of a VP.'''
        return self.GetRegisters64(
            VpIndex,
            [whv.WHvX64RegisterRip]
        )[0]

    def DumpRegisters(self, VpIndex):
        '''Dump the register of a VP.'''
        R = self.GetRegisters(
            VpIndex, [
                whv.WHvX64RegisterRax, whv.WHvX64RegisterRbx, whv.WHvX64RegisterRcx,
                whv.WHvX64RegisterRdx, whv.WHvX64RegisterRsi, whv.WHvX64RegisterRdi,
                whv.WHvX64RegisterRip, whv.WHvX64RegisterRsp, whv.WHvX64RegisterRbp,
                whv.WHvX64RegisterR8, whv.WHvX64RegisterR9, whv.WHvX64RegisterR10,
                whv.WHvX64RegisterR11, whv.WHvX64RegisterR12, whv.WHvX64RegisterR13,
                whv.WHvX64RegisterR14, whv.WHvX64RegisterR15,
                whv.WHvX64RegisterCs, whv.WHvX64RegisterSs, whv.WHvX64RegisterDs,
                whv.WHvX64RegisterEs, whv.WHvX64RegisterFs, whv.WHvX64RegisterGs,
                whv.WHvX64RegisterRflags
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

        print 'cs=%04x ss=%04x ds=%04x es=%04x fs=%04x gs=%04x   efl=%08x' % (
            R[17].Segment.Selector,
            R[18].Segment.Selector,
            R[19].Segment.Selector,
            R[20].Segment.Selector,
            R[21].Segment.Selector,
            R[22].Segment.Selector,
            Rflags
        )

    def MapGpaRange(self, Buffer, GuestAddress, Flags):
        '''Map physical memory into the partition backed by process virtual-memory.'''
        SizeInBytes = Align2Page(len(Buffer))
        # XXX: Figure out ressource clean-up.
        SourceBuffer = VirtualAlloc(
            0,
            SizeInBytes,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )

        assert SourceBuffer is not None, 'VirtualAlloc failed.'
        ct.memmove(SourceBuffer, Buffer, len(Buffer))

        Success, Ret = WHvMapGpaRange(
            self.Partition,
            SourceBuffer,
            GuestAddress,
            SizeInBytes,
            Flags
        )

        assert Success, 'WHvMapGpaRange failed with %x.' % Ret
        return (SourceBuffer, SizeInBytes)

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

class WHvPartitionConfig32b(object):
    def __init__(self, Partition):
        '''Configure a 32b execution environment'''


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
    '''Return a string representation of Cr0.'''
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

    PartitionOptions = {
        'ProcessorCount' : 1,
        'ExceptionExitBitmap' : whv.WHvX64ExceptionTypeBreakpointTrap,
        'Name' : '32b kernel'
    }

    IDT_GPA = 0xffff0000
    CODE_GPA = 0x0
    with WHvPartition(**PartitionOptions) as Partition:
        print 'Partition created:', Partition

        InitialRip = Partition.GetRip(0)
        assert InitialRip == 0xfff0, 'The initial @rip(%x) does not match with expected value.' % InitialRip
        print 'Initial @rip in VP0:', hex(InitialRip)

        GuestCodePageAddress, _ = Partition.MapGpaRange(
            # inc eax ; ... ; int3
            '\x40' * 0x1337 + '\xcc',
            CODE_GPA,
            'rx'
        )

        print 'Mapped GPA:%x backed by memory at %016x' % (
            CODE_GPA,
            GuestCodePageAddress
        )

        Cr0, Gdtr, Idtr = Partition.GetRegisters(0, (
                whv.WHvX64RegisterCr0,
                whv.WHvX64RegisterGdtr,
                whv.WHvX64RegisterIdtr
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
                whv.WHvX64RegisterRip : CODE_GPA,
                whv.WHvX64RegisterCs : Generate32bCodeSegment(),
                whv.WHvX64RegisterIdtr : Idtr,
                #whv.WHvX64RegisterCr0 : Cr0.Reg64 | 1
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
                whv.WHvX64RegisterRip,
                whv.WHvX64RegisterRax
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
