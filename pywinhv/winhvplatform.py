# Axel '0vercl0k' Souchet - 23 January 2019
from pywinhv import *
import sys

getsizeof = sys.getsizeof

def HypervisorPresent():
    '''Is the support for the Hypervisor Platform APIs
    enabled?'''
    Capabilities = WHV_CAPABILITY()
    ReturnLength = new_PUINT32()
    PUINT32_assign(ReturnLength, 0)
    assert WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent,
        Capabilities,
        getsizeof(Capabilities),
        ReturnLength
    ) == 0, 'WHvGetCapability failed'

    assert PUINT32_value(ReturnLength) == 4, 'The return length should be sizeof(BOOL)'
    return Capabilities.HypervisorPresent == 1

def main(argc, argv):
    print 'HypervisorPresent:', HypervisorPresent()

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
