# Axel '0vercl0k' Souchet - 20 January 2019
import sys
sys.path.append('..')
from pywinhv import *

getsizeof = sys.getsizeof

def main(argc, argv):
    Capabilities = WHV_CAPABILITY()
    ReturnLength = new_PUINT32()
    PUINT32_assign(ReturnLength, 0)
    assert WHvGetCapability(
        WHvCapabilityCodeHypervisorPresent,
        Capabilities,
        getsizeof(Capabilities),
        ReturnLength
    ) == 0, 'WHvGetCapability failed'

    print 'HyperviorPresent:', Capabilities.HypervisorPresent == 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))

