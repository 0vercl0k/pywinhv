# Axel '0vercl0k' Souchet - February 7th 2019
import winhvplatform as hvplat
import pywinhv as whv
import vp
import utils

import ctypes as ct
import sys
from ctypes.wintypes import BOOL, LPVOID, DWORD, c_size_t as SIZE_T
from collections import namedtuple

ct.windll.kernel32.VirtualAlloc.argtypes = (LPVOID, SIZE_T, DWORD, DWORD)
ct.windll.kernel32.VirtualAlloc.restype = LPVOID
VirtualAlloc = ct.windll.kernel32.VirtualAlloc

ct.windll.kernel32.VirtualFree.argtypes = (LPVOID, SIZE_T, DWORD)
ct.windll.kernel32.VirtualFree.restype = BOOL
VirtualFree = ct.windll.kernel32.VirtualFree

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04

TranslationTableEntry_t = namedtuple(
    'TranslationTableEntry_t', (
        'Gva', 'Hva', 'Flags'
    )
)

class WHvPartition(object):
    '''This is the Python abstraction for a Partition. The class
    can also be used a context manager. In this class, a lot of efforts are taken
    to hide a bunch of the WinHvPlatform APIs underlying details.
    On top of that, it makes invoking the raw APIs (exposed by SWIG) more pythonic.
    As there are a bunch of different addresses, I have tried to follow the following
    convention:
        * Partition object represent a 'guest',
        * The process from which you are instantiating the Partition is the 'host',
        * As a result - there are always three different addresses describing the same
          piece of memory:
          * The address in the host virtual address-space is an HVA,
          * The address in the guest virtual address-space is a GVA,
          * The address in the guest physical address-space is a GPA.
    '''
    def __init__(self, **kwargs):
        '''Create and setup a Partition object.'''
        assert utils.IsHypervisorPresent(), 'The hypervisor platform APIs support must be turned on.'
        self.ProcessorCount = kwargs.get('ProcessorCount', 1)
        self.Name = kwargs.get('Name', 'DefaultName')
        self.ExceptionExitBitmap = kwargs.get('ExceptionExitBitmap', 0)
        # XXX: OrderedDict might be better?
        self.TranslationTable = {}
        self.Processors = []

        # Create the partition.
        Success, Handle, Ret = hvplat.WHvCreatePartition()
        assert Success, 'WHvCreatePartition failed in context manager with %x.' % Ret
        self.Handle = Handle

        # Set-up the partition with a number of VPs.
        Property = whv.WHV_PARTITION_PROPERTY()
        Property.ProcessorCount = self.ProcessorCount
        Success, Ret = hvplat.WHvSetPartitionProperty(
            self.Handle,
            whv.WHvPartitionPropertyCodeProcessorCount,
            Property
        )
        assert Success, 'WHvSetPartitionProperty(ProcessorCount) failed in context manager with %x.' % Ret

        # Set-up Exception exits.
        Property.ExtendedVmExits.ExceptionExit = 1
        Success, Ret = hvplat.WHvSetPartitionProperty(
            self.Handle,
            whv.WHvPartitionPropertyCodeExtendedVmExits,
            Property
        )
        assert Success, 'WHvSetPartitionProperty(ExtendedVmExits) failed in context manager with %x.' % Ret

        # Set-up the ExceptionExitBitmap.
        Property.ExceptionExitBitmap  = 1 << whv.WHvX64ExceptionTypeBreakpointTrap
        Property.ExceptionExitBitmap |= 1 << whv.WHvX64ExceptionTypePageFault
        Property.ExceptionExitBitmap |= 1 << whv.WHvX64ExceptionTypeGeneralProtectionFault
        Success, Ret = hvplat.WHvSetPartitionProperty(
            self.Handle,
            whv.WHvPartitionPropertyCodeExceptionExitBitmap,
            Property
        )
        assert Success, 'WHvSetPartitionProperty(ExceptionExitBitmap) failed in context manager with %x.' % Ret

        # Activate the partition.
        Success, Ret = hvplat.WHvSetupPartition(self.Handle)
        assert Success, 'WHvSetupPartition failed in context manager with %x.' % Ret

        # Create the virtual processors.
        for VpIndex in range(self.ProcessorCount):
            Success, Ret = hvplat.WHvCreateVirtualProcessor(
                self.Handle,
                VpIndex
            )

            assert Success, 'WHvCreateVirtualProcessor(%d) failed in context manager with %x.' % (VpIndex, Ret)

            Vp = vp.WHvVirtualProcessor(
                self.Handle,
                self,
                VpIndex
            )

            self.Processors.append(Vp)

    @classmethod
    def CreateDefault(cls, Name = 'default'):
        '''Create a default partition with a single VP.'''

        Partition = cls(
            ProcessorCount = 1,
            Name = Name,
        )

        return Partition

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        BlockHasThrown = etype is not None

        # Release the VPs.
        for Vp in self.Processors:
            Success, Ret = hvplat.WHvDeleteVirtualProcessor(
                self.Handle,
                Vp.Index
            )

            assert Success, 'WHvDeleteVirtualProcessor failed in context manager with %x.' % Ret

        # Release the Partition.
        Success, Ret = hvplat.WHvDeletePartition(self.Handle)
        assert Success, 'WHvDeletePartition failed in context manager with %x.' % Ret

        # XXX: Release memory
        self.TranslationTable = {}

        # Forward the exception is we've intercepted one, otherwise s'all good.
        return not BlockHasThrown

    def __repr__(self):
        '''Pretty-pinter for the Partition object.'''
        return 'Partition(%r, ProcessorCount=%d)' % (
            self.Name,
            self.ProcessorCount
        )

    def GetVp(self, Index):
        '''Get a VP instance.'''
        assert Index < self.ProcessorCount
        return self.Processors[Index]

    def MapGpaRangeWithoutContent(self, Gpa, SizeInBytes, Flags):
        '''Map a GPA range in the partition. This takes care of allocating
        memory in the host and mapping it in the guest.'''
        SizeInBytes = utils.Align2Page(SizeInBytes)
        Hva = VirtualAlloc(
            0,
            SizeInBytes,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )

        assert Hva is not None, 'VirtualAlloc failed.'

        if 'd' not in Flags:
            # Force the 'd' dirty flag that is used for save/restore.
            Flags += 'd'

        WHvFlags = whv.WHvMapGpaRangeFlagNone
        if 'r' in Flags:
            WHvFlags |= whv.WHvMapGpaRangeFlagRead

        if 'w' in Flags:
            WHvFlags |= whv.WHvMapGpaRangeFlagWrite

        if 'x' in Flags:
            WHvFlags |= whv.WHvMapGpaRangeFlagExecute

        if 'd' in Flags:
            WHvFlags |= whv.WHvMapGpaRangeFlagTrackDirtyPages

        Success, Ret = hvplat.WHvMapGpaRange(
            self.Handle,
            Hva,
            Gpa,
            SizeInBytes,
            WHvFlags
        )

        assert Success, 'WHvMapGpaRange failed with: %s.' % hvplat.WHvReturn(Ret)

        # Break the range into a series of pages for the translation table.
        for Idx in range(SizeInBytes / 0x1000):
            CurGpa = Gpa + (Idx * 0x1000)
            CurHva = Hva + (Idx * 0x1000)
            self.TranslationTable[CurGpa] = TranslationTableEntry_t(
                CurGpa, CurHva, Flags
            )

        return (Hva, Gpa, SizeInBytes)

    def MapGpaRange(self, Gpa, Buffer, Flags):
        '''Map a GPA range in the partition and initialize it with content.'''
        Hva, _, SizeInBytes = self.MapGpaRangeWithoutContent(
            Gpa,
            len(Buffer),
            Flags
        )

        ct.memmove(Hva, Buffer, len(Buffer))
        return (Hva, SizeInBytes)

    def MapCode(self, Code, Gpa, Writeable = False):
        '''Map a GPA range used to host code in the partition.'''
        Flags = 'rx'

        if Writeable:
            Flags += 'w'

        Hva, CodeLength = self.MapGpaRange(
            Gpa,
            Code,
            Flags
        )

        return (Hva, CodeLength)

    def UnmapGpaRange(self, Gpa, SizeInBytes, Hva = None):
        '''Unmap a GPA range and release the backing host memory page if provided.'''
        hvplat.WHvUnmapGpaRange(
            self.Handle,
            Gpa,
            SizeInBytes
        )

        if Hva is None:
            return

        Success = VirtualFree(
            Hva,
            SizeInBytes,
            0
        ) == 0

        assert Success, 'VirtualFree failed.'

    def TranslateGpa(self, Gpa):
        '''Translate a GPA to an HVA. This is only possible because we
        keep track of every call made to map GPA ranges and store the HVA/GPA.'''
        GpaAligned, Offset = utils.SplitAddress(Gpa)
        Entry = self.TranslationTable.get(GpaAligned, None)
        if Entry is not None:
            return Entry.Hva + Offset

        return None

    def GetPartitionCounters(self, Counter):
        '''Get a partition performance counter.'''
        Success, Counters, Ret = hvplat.WHvGetPartitionCounters(
            self.Handle,
            Counter
        )

        assert Success, 'WHvGetPartitionCounters failed with: %s.' % hvplat.WHvReturn(Ret)
        return Counters


    def QueryGpaRangeDirtyBitmap(self, Gpa, RangeSize):
        '''Get a list of bits describing which physical guest page is dirty. One bit per
        page.'''
        Success, Bits, Ret = hvplat.WHvQueryGpaRangeDirtyBitmap(
            self.Handle,
            Gpa,
            RangeSize
        )

        assert Success, 'WHvQueryGpaRangeDirtyBitmap failed with: %s.' % hvplat.WHvReturn(Ret)
        return Bits

    def ClearGpaRangeDirtyPages(self, Gpa, RangeSize):
        '''Clear the dirty bits on a GPA range.'''
        Success, _, Ret = hvplat.WHvQueryGpaRangeDirtyBitmap(
            self.Handle,
            Gpa,
            RangeSize,
            True
        )

        assert Success, 'WHvQueryGpaRangeDirtyBitmap failed with: %s.' % hvplat.WHvReturn(Ret)

    def ClearGpaDirtyPage(self, Gpa):
        '''Clear the dirty bit for a specific GPA page.'''
        return self.ClearGpaRangeDirtyPages(
            Gpa,
            0x1000
        )

    def QueryGpaRangeDirtyPages(self, Gpa, RangeSize):
        '''Get a list of the dirty GPAs.'''
        Bits = self.QueryGpaRangeDirtyBitmap(
            Gpa,
            RangeSize
        )

        DirtyPages = []
        CurGpa = Gpa
        for Bit in Bits:
            if Bit:
                DirtyPages.append(CurGpa)
            CurGpa += 0x1000

        return DirtyPages

    def IsGpaDirty(self, Gpa):
        '''Is the GPA page dirty or not?'''
        return self.QueryGpaRangeDirtyBitmap(
            Gpa,
            0x1000
        )[0]

    def Save(self):
        '''Save a snapshot of the virtual processors registers as well as the physical
        memory space. It can be restored with Restore.'''
        Snapshot = {
            'VP' : [],
            'Mem' : {},
            'Table' : self.GetTranslationTable()
        }

        # XXX: SpecCtrl & cie, ensure they are available in the VP.
        for Vp in self.Processors:
            Registers = Vp.GetRegisters(hvplat.AllRegisters)
            Snapshot['VP'].append((
                Vp.Index,
                Registers
            ))

        for Gpa, Entry in self.TranslationTable.iteritems():
            # Don't save pages that are not writeable.
            if 'w' not in Entry.Flags:
                continue

            PageContent = ct.string_at(Entry.Hva, 0x1000)
            Snapshot['Mem'][Gpa] = (
                Entry.Hva, PageContent
            )

        self.ClearGpaRangeDirtyPages(
            0,
            # XXX: This assumes that the physical address space is packed and that
            # there is no hole.
            len(self.TranslationTable) * 0x1000
        )

        return Snapshot

    def Restore(self, Snapshot):
        '''Restore a snapshot into the partition.'''
        for VpIndex, Registers in Snapshot['VP']:
            Vp = self.GetVp(VpIndex)
            Vp.SetRegisters(
                # XXX: Something cleaner maybe?
                dict(zip(hvplat.AllRegisters, Registers))
            )

        # Force a copy of the table.
        self.TranslationTable = dict(Snapshot['Table'])

        if False:
            # XXX: It's sound to be slower..?
            DirtyGpas = self.QueryGpaRangeDirtyPages(
                0,
                # XXX: This assumes that the physical address space is packed and that
                # there is no hole.
               len(self.TranslationTable) * 0x1000
            )

            # Restore the dirty memory that has been saved off.
            for DirtyGpa in DirtyGpas:
                Hva, PageContent = Snapshot['Mem'].get(DirtyGpa)
                ct.memmove(Hva, PageContent, 0x1000)
        else:
            # Restore the dirty memory that has been saved off.
            for Hva, PageContent in Snapshot['Mem'].itervalues():
                ct.memmove(Hva, PageContent, 0x1000)

        self.ClearGpaRangeDirtyPages(
            0,
            # XXX: This assumes that the physical address space is packed and that
            # there is no hole.
            len(self.TranslationTable) * 0x1000
        )

    def GetTranslationTable(self):
        '''Return a copy of the translation table.'''
        return dict(self.TranslationTable)


def main(argc, argv):
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))

