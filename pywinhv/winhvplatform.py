# Axel '0vercl0k' Souchet - 23 January 2019
import pywinhv as whv
import sys
from enum import Enum

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
    RegisterNamesValues = {}
    if Success:
        for Idx, RegisterName in enumerate(Registers):
            RegisterNamesValues[RegisterName] = RegisterValues[Idx].Reg64

    return (Success, RegisterNamesValues, Ret)

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
        # XXX: Not sure why RegisterValues[Idx].Reg64 = 0xdeadbeef doesnt work.
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
    return (Success, Ret)

class WHvPartition(object):
    '''Context manager for Partition.'''
    def __init__(self, Name = 'DefaultName', ProcessorCount = 1):
        '''Create and setup a Partition object.'''
        self.ProcessorCount = ProcessorCount
        self.Name = Name

        # Create the partition.
        Success, Partition, Ret = WHvCreatePartition()
        assert Success, 'WHvCreatePartition failed in context manager with %x.' % Ret
        self.Partition = Partition

        # Set up the partition
        Property = whv.WHV_PARTITION_PROPERTY()
        Property.ProcessorCount = ProcessorCount
        Success, Ret = WHvSetPartitionProperty(
            self.Partition,
            whv.WHvPartitionPropertyCodeProcessorCount,
            Property
        )
        assert Success, 'WHvSetPartitionProperty failed in context manager with %x.' % Ret

        # Activate the partition.
        Success, Ret = WHvSetupPartition(self.Partition)
        assert Success, 'WHvSetupPartition failed in context manager with %x.' % Ret

        # Create the virtual processors.
        for VpIndex in range(self.ProcessorCount):
            Success, Ret = WHvCreateVirtualProcessor(
                self.Partition,
                VpIndex
            )
            assert Success, 'WHvCreateVirtualProcessor(%d) failed in context manager with %x' % (VpIndex, Ret)

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
        return 'Partition(%s, ProcessorCount=%d)' % (
            self.Name,
            self.ProcessorCount
        )

    def RunVp(self, VpIndex):
        '''Run the virtual processor'''
        Success, ExitContext, Ret = WHvRunVirtualProcessor(
            self.Partition, VpIndex
        )

        if not Success:
            raise RuntimeError('WHvRunVirtualProcessor failed with %x.' % Ret)

        return ExitContext

    def SetRegisters(self, VpIndex, Registers):
        '''Set registers in a VP'''
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

    def GetRegisters(self, VpIndex, Registers):
        '''Get registers of a VP'''
        Success, Registers, Ret = WHvGetVirtualProcessorRegisters(
            self.Partition,
            VpIndex,
            Registers
        )

        assert Success, 'GetRegisters failed with %x.' % Ret
        return Registers

    def GetRip(self, VpIndex):
        '''Get the @rip register of a VP'''
        return self.GetRegisters(
            VpIndex,
            [whv.WHvX64RegisterRip]
        )[whv.WHvX64RegisterRip]

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

def IsHypervisorPresent():
    '''Is the support for the Hypervisor Platform APIs
    enabled?'''
    Capabilities = whv.WHV_CAPABILITY()
    Success, _, _ = WHvGetCapability(
        whv.WHvCapabilityCodeHypervisorPresent,
        Capabilities
    )

    return Success and Capabilities.HypervisorPresent == 1

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

    with WHvPartition(ProcessorCount = 1) as Partition:
        print 'Partition created:', Partition

        InitialRip = Partition.GetRip(0)
        assert InitialRip == 0xfff0, 'The initial RIP(%x) does not match with expected value.' % InitialRip
        print 'Initial @rip in VP0:', hex(InitialRip)

        Partition.SetRip(0, 0xdeadbeefbaadc0de)
        Rip = Partition.GetRip(0)
        print '@rip in VP0:', hex(Rip)

        ExitContext = Partition.RunVp(0)
        ExitReason = WHvExitReason(ExitContext.ExitReason)
        if not (ExitReason.value == whv.WHvRunVpExitReasonInvalidVpRegisterValue):
            raise RuntimeError('The VP did not exit with the appropriate ExitReason(%r)' % ExitReason)
        print 'Partition exited with:', ExitReason

        Rip = Partition.GetRip(0)
        assert Rip == 0xdeadbeefbaadc0de, 'The @rip(%x) register in VP0 sounds bogus.' % Rip
        print '@rip after run:', hex(Rip)

    print 'All good!'
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
