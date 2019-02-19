# Axel '0vercl0k' Souchet - February 7th 2019
import winhvplatform as hvplat
import pywinhv as whv
import ctypes as ct
import utils
import sys
from ctypes.wintypes import BOOL, LPVOID, DWORD, c_size_t as SIZE_T

ct.windll.kernel32.VirtualAlloc.argtypes = (LPVOID, SIZE_T, DWORD, DWORD)
ct.windll.kernel32.VirtualAlloc.restype = LPVOID
VirtualAlloc = ct.windll.kernel32.VirtualAlloc

ct.windll.kernel32.VirtualFree.argtypes = (LPVOID, SIZE_T, DWORD)
ct.windll.kernel32.VirtualFree.restype = BOOL
VirtualFree = ct.windll.kernel32.VirtualFree

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04

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

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        BlockHasThrown = etype is not None

        # Release the VPs.
        for VpIndex in range(self.ProcessorCount):
            Success, Ret = hvplat.WHvDeleteVirtualProcessor(
                self.Handle,
                VpIndex
            )
            assert Success, 'WHvDeleteVirtualProcessor failed in context manager with %x.' % Ret

        # Release the Partition.
        Success, Ret = hvplat.WHvDeletePartition(self.Handle)
        assert Success, 'WHvDeletePartition failed in context manager with %x.' % Ret

        # Forward the exception is we've intercepted one, otherwise s'all good.
        return not BlockHasThrown

    def __repr__(self):
        '''Pretty-pinter for the Partition object.'''
        return 'Partition(%r, ProcessorCount=%d)' % (
            self.Name,
            self.ProcessorCount
        )

    def RunVp(self, VpIndex):
        '''Run the virtual processor.'''
        Success, ExitContext, Ret = hvplat.WHvRunVirtualProcessor(
            self.Handle, VpIndex
        )

        assert Success, 'WHvRunVirtualProcessor failed with: %s.' % hvplat.WHvReturn(Ret)
        return ExitContext, hvplat.WHvExitReason(ExitContext.ExitReason)

    def SetRegisters(self, VpIndex, Registers):
        '''Set registers in a VP.'''
        Success, Ret = hvplat.WHvSetVirtualProcessorRegisters(
            self.Handle,
            VpIndex,
            Registers
        )

        assert Success, 'WHvSetVirtualProcessorRegisters failed with: %s.' % hvplat.WHvReturn(Ret)

    def SetRip(self, VpIndex, Rip):
        '''Set the @rip register of a VP.'''
        return self.SetRegisters(
            VpIndex, {
                hvplat.Rip: Rip
            }
        )

    def GetRegisters(self, VpIndex, Registers, Reg64 = False):
        '''Get registers of a VP.'''
        Success, Registers, Ret = hvplat.WHvGetVirtualProcessorRegisters(
            self.Handle,
            VpIndex,
            Registers
        )

        assert Success, 'GetRegisters failed with: %s.' % hvplat.WHvReturn(Ret)
        if Reg64:
            Registers = map(
                lambda R: R.Reg64,
                Registers
            )

        return Registers

    def GetRegisters64(self, VpIndex, Registers):
        '''Get VP registers and return the .Reg64 part.'''
        return self.GetRegisters(VpIndex, Registers, Reg64 = True)

    def GetRegister(self, VpIndex, Register):
        '''Get a single VP register.'''
        return self.GetRegisters(
            VpIndex,
            (Register, )
        )[0]

    def GetRegister64(self, VpIndex, Register):
        '''Get a VP register.'''
        return self.GetRegister(
            VpIndex,
            Register,
        ).Reg64

    def GetRip(self, VpIndex):
        '''Get the @rip register of a VP.'''
        return self.GetRegisters64(
            VpIndex,
            (hvplat.Rip, )
        )[0]

    def DumpRegisters(self, VpIndex):
        '''Dump the register of a VP.'''
        R = self.GetRegisters(
            VpIndex, [
                hvplat.Rax, hvplat.Rbx, hvplat.Rcx, hvplat.Rdx, hvplat.Rsi, hvplat.Rdi,
                hvplat.Rip, hvplat.Rsp, hvplat.Rbp, hvplat.R8, hvplat.R9, hvplat.R10,
                hvplat.R11, hvplat.R12, hvplat.R13, hvplat.R14, hvplat.R15,
                hvplat.Cs, hvplat.Ss, hvplat.Ds, hvplat.Es, hvplat.Fs, hvplat.Gs,
                hvplat.Rflags, hvplat.Cr3
            ]
        )

        print 'rax=%016x rbx=%016x rcx=%016x' % (
            R[0].Reg64, R[1].Reg64, R[2].Reg64
        )

        print 'rdx=%016x rsi=%016x rdi=%016x' % (
            R[3].Reg64, R[4].Reg64, R[5].Reg64
        )

        Rip = R[6].Reg64
        print 'rip=%016x rsp=%016x rbp=%016x' % (
            Rip, R[7].Reg64, R[8].Reg64
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

        Code = '???'
        Hva = self.TranslateGvaToHva(
            VpIndex,
            Rip
        )

        if Hva is not None:
            HowManyLeft = 0x1000 - (Hva & 0xfff)
            HowMany = min(HowManyLeft, 16)
            Code = ct.string_at(Hva, HowMany)

        print '%016x' % Rip, Code.encode('hex')

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
        self.TranslationTable[Gpa] = Hva
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

    def TranslateGva(self, VpIndex, Gva, Flags = None):
        '''Translate a GVA into a GPA.'''
        if Flags is None:
            Flags = 're'

        WHvFlags = whv.WHvTranslateGvaFlagNone
        if 'r' in Flags:
            WHvFlags |= whv.WHvTranslateGvaFlagValidateRead
        if 'w' in Flags:
            WHvFlags |= whv.WHvTranslateGvaFlagValidateWrite
        if 'x' in Flags:
            WHvFlags |= whv.WHvTranslateGvaFlagValidateExecute
        if 'e' in Flags:
            WHvFlags |= whv.WHvTranslateGvaFlagPrivilegeExempt

        Success, ResultCode, Gpa, Ret = hvplat.WHvTranslateGva(
            self.Handle,
            VpIndex,
            Gva,
            WHvFlags
        )

        assert Success, 'WHvTranslateGva failed with: %s.' % hvplat.WHvReturn(Ret)
        return (hvplat.WHvTranslateGvaResultCode(ResultCode), Gpa)

    def TranslateGpa(self, Gpa):
        '''Translate a GPA to an HVA. This is only possible because we
        keep track of every call made to map GPA ranges and store the HVA/GPA.'''
        GpaAligned, Offset = utils.SplitAddress(Gpa)
        Hva = self.TranslationTable.get(GpaAligned, None)
        if Hva is not None:
            return Hva + Offset
        return None

    def TranslateGvaToHva(self, VpIndex, Gva, Flags = None):
        '''Translate a GVA to an HVA. This combines TranslateGva / TranslateGpa to
        go from a GVA to an HVA.'''
        GvaAligned, Offset = utils.SplitAddress(Gva)
        ResultCode, Gpa = self.TranslateGva(
            VpIndex,
            GvaAligned,
            Flags
        )

        assert ResultCode.value == whv.WHvTranslateGvaResultSuccess, 'TranslateGva(%x) failed with %s' % (Gva, ResultCode)
        Hva = self.TranslateGpa(Gpa)
        if Hva is None:
            return None
        return Hva + Offset

    def GetPartitionCounters(self, Counter):
        '''Get a partition performance counter.'''
        Success, Counters, Ret = hvplat.WHvGetPartitionCounters(
            self.Handle,
            Counter
        )

        assert Success, 'WHvGetPartitionCounters failed with: %s.' % hvplat.WHvReturn(Ret)
        return Counters

    def GetVpCounters(self, VpIndex, Counter):
        '''Get a virtual processor performance counter.'''
        Success, Counters, Ret = hvplat.WHvGetVirtualProcessorCounters(
            self.Handle,
            VpIndex,
            Counter
        )

        assert Success, 'WHvGetVirtualProcessorCounters failed with: %s.' % hvplat.WHvReturn(Ret)

        Result = {
            whv.WHvProcessorCounterSetRuntime : Counters.Runtime,
            whv.WHvProcessorCounterSetIntercepts : Counters.Intercepts,
            whv.WHvProcessorCounterSetEvents : Counters.GuestEvents,
            whv.WHvProcessorCounterSetApic : Counters.Apic
        }.get(Counter, None)

        assert Result is not None, 'Counter(%x) has not been added to WHV_PROCESSOR_ALL_COUNTERS?' % Counter

        return Result

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
            'Mem' : [],
        }

        # XXX: SpecCtrl & cie, ensure they are available in the VP.
        for VpIndex in range(self.ProcessorCount):
            Registers = self.GetRegisters(
                VpIndex,
                hvplat.AllRegisters
            )

            Snapshot['VP'].append((VpIndex, Registers))

        for Gpa, Hva in self.TranslationTable.iteritems():
            Page = ct.string_at(Hva, 0x1000)
            Snapshot['Mem'].append((
                Gpa, Hva, Page
            ))

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
            self.SetRegisters(
                VpIndex,
                # XXX: Something cleaner maybe?
                dict(zip(hvplat.AllRegisters, Registers))
            )

        # XXX: Don't restore read-only pages?
        self.TranslationTable = {}
        for Gpa, Hva, Page in Snapshot['Mem']:
            ct.memmove(Hva, Page, 0x1000)
            self.TranslationTable[Gpa] = Hva

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

