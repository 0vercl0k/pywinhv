# Axel '0vercl0k' Souchet - February 7th 2019
import winhvplatform as hvplat
import pywinhv as whv
import ctypes as ct
import utils
import sys
from ctypes.wintypes import LPVOID, DWORD, c_size_t as SIZE_T

ct.windll.kernel32.VirtualAlloc.argtypes = (LPVOID, SIZE_T, DWORD, DWORD)
ct.windll.kernel32.VirtualAlloc.restype = LPVOID
VirtualAlloc = ct.windll.kernel32.VirtualAlloc

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04

class WHvPartition(object):
    '''Context manager for Partition.'''
    def __init__(self, **kwargs):
        '''Create and setup a Partition object.'''
        assert utils.IsHypervisorPresent(), 'The hypervisor platform APIs support must be turned on.'
        self.CurrentGpa = 0
        self.ProcessorCount = kwargs.get('ProcessorCount', 1)
        self.Name = kwargs.get('Name', 'DefaultName')
        self.ExceptionExitBitmap = kwargs.get('ExceptionExitBitmap', 0)
        self.TranslationTable = {}

        # Create the partition.
        Success, Partition, Ret = hvplat.WHvCreatePartition()
        assert Success, 'WHvCreatePartition failed in context manager with %x.' % Ret
        self.Partition = Partition

        # Set-up the partition with a number of VPs.
        Property = whv.WHV_PARTITION_PROPERTY()
        Property.ProcessorCount = self.ProcessorCount
        Success, Ret = hvplat.WHvSetPartitionProperty(
            self.Partition,
            whv.WHvPartitionPropertyCodeProcessorCount,
            Property
        )
        assert Success, 'WHvSetPartitionProperty(ProcessorCount) failed in context manager with %x.' % Ret

        # Set-up Exception exits.
        Property.ExtendedVmExits.ExceptionExit = 1
        Success, Ret = hvplat.WHvSetPartitionProperty(
            self.Partition,
            whv.WHvPartitionPropertyCodeExtendedVmExits,
            Property
        )
        assert Success, 'WHvSetPartitionProperty(ExtendedVmExits) failed in context manager with %x.' % Ret

        # Set-up the ExceptionExitBitmap.
        Property.ExceptionExitBitmap = 1 << whv.WHvX64ExceptionTypeBreakpointTrap
        Success, Ret = hvplat.WHvSetPartitionProperty(
            self.Partition,
            whv.WHvPartitionPropertyCodeExceptionExitBitmap,
            Property
        )
        assert Success, 'WHvSetPartitionProperty(ExceptionExitBitmap) failed in context manager with %x.' % Ret

        # Activate the partition.
        Success, Ret = hvplat.WHvSetupPartition(self.Partition)
        assert Success, 'WHvSetupPartition failed in context manager with %x.' % Ret

        # Create the virtual processors.
        for VpIndex in range(self.ProcessorCount):
            Success, Ret = hvplat.WHvCreateVirtualProcessor(
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
            Success, Ret = hvplat.WHvDeleteVirtualProcessor(
                self.Partition,
                VpIndex
            )
            assert Success, 'WHvDeleteVirtualProcessor failed in context manager with %x.' % Ret

        # Release the Partition.
        Success, Ret = hvplat.WHvDeletePartition(self.Partition)
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
        Success, ExitContext, Ret = hvplat.WHvRunVirtualProcessor(
            self.Partition, VpIndex
        )

        assert Success, ('WHvRunVirtualProcessor failed with %x.' % Ret)
        return ExitContext

    def SetRegisters(self, VpIndex, Registers):
        '''Set registers in a VP.'''
        Success, Ret = hvplat.WHvSetVirtualProcessorRegisters(
            self.Partition,
            VpIndex,
            Registers
        )

        assert Success, 'WHvSetVirtualProcessorRegisters failed with %x.' % Ret

    def SetRip(self, VpIndex, Rip):
        '''Set the @rip register of a VP'''
        return self.SetRegisters(
            VpIndex, {
                hvplat.Rip: Rip
            }
        )

    def GetRegisters(self, VpIndex, Registers, Reg64 = False):
        '''Get registers of a VP.'''
        Success, Registers, Ret = hvplat.WHvGetVirtualProcessorRegisters(
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
        SizeInBytes = utils.Align2Page(SizeInBytes)
        Hva = VirtualAlloc(
            0,
            SizeInBytes,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )

        assert Hva is not None, 'VirtualAlloc failed.'

        Success, Ret = hvplat.WHvMapGpaRange(
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
        return (Hva, SizeInBytes)

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

        Success, ResultCode, Gpa, Ret = hvplat.WHvTranslateGva(
            self.Partition,
            VpIndex,
            Gva,
            Flags
        )

        assert Success, 'WHvTranslateGva failed with: %x.' % Ret
        return (hvplat.WHvTranslateGvaResultCode(ResultCode), Gpa)

    def TranslateGpa(self, Gpa):
        '''Translate a Gpa to an Hva.'''
        Offset, GpaAligned = Gpa & 0xfff, Gpa & 0xfffffffffffff000
        Hva = self.TranslationTable.get(GpaAligned, None)
        if Hva is not None:
            return Hva + Offset
        return None

    def TranslateGvaToHva(self, VpIndex, Gva, Flags = None):
        '''Translate a Gva to an Hva.'''
        if Flags is None:
            Flags = whv.WHvTranslateGvaFlagValidateRead | whv.WHvTranslateGvaFlagPrivilegeExempt

        Offset, GvaAligned = Gva & 0xfff, Gva & 0xfffffffffffff000
        ResultCode, Gpa = self.TranslateGva(
            VpIndex,
            GvaAligned,
            Flags
        )

        assert ResultCode.value == whv.WHvTranslateGvaResultSuccess, 'TranslateGva(%x) failed with %s' % (Gva, ResultCode)
        return self.TranslateGpa(Gpa)

    def GetPartitionCounters(self, Counter):
        '''Get partition counters.'''
        Success, Counters, Ret = hvplat.WHvGetPartitionCounters(
            self.Partition,
            Counter
        )

        assert Success, 'WHvGetPartitionCounters failed with: %x.' % Ret
        return Counters
