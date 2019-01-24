# Axel '0vercl0k' Souchet - 23 January 2019
import pywinhv as whv
import sys

getsizeof = sys.getsizeof

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
    CapabilityBufferSize = getsizeof(CapabilityBuffer)
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
    return (Success, ReturnLengthValue, Ret)

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
    return (Success, PartitionValue, Ret)

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
    return (Success, Ret)

class WHvPartition(object):
    '''Context manager for Partition.'''
    def __init__(self):
        Success, Partition, Ret = WHvCreatePartition()
        assert Success, 'WHvCreatePartition failed in context manager: %x.' % Ret
        self.Partition = Partition

    def __enter__(self):
        return self.Partition

    def __exit__(self, etype, value, traceback):
        BlockHasThrown = etype is not None
        Success, Ret = WHvDeletePartition(self.Partition)
        assert Success, 'WHvDeletePartition failed in context manager" %x.' % Ret
        # Forward the exception is we've intercepted one, otherwise s'all good.
        return not BlockHasThrown

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

    with WHvPartition() as Partition:
        print 'Partition created:', Partition

    print 'All good!'
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
