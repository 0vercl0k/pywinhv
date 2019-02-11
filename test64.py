# Axel '0vercl0k' Souchet - February 7th 2019
import pywinhv as hv
import sys
import struct
import unittest
from ctypes import memmove

# mov rax, Address ; mov rbx, Value ; mov [rax], rbx
WriteMemory64 = lambda Address, Value: '\x48\xb8' + struct.pack('<Q', Address) + '\x48\xbb' + struct.pack('<Q', Value) + '\x48\x89\x18'
# mov rax, Address ; mov rax, [rax]
ReadMemory64 = lambda Address: '\x48\xb8' + struct.pack('<Q', Address) + '\x48\x8b\x00'
# mov rax, gs:[0]
LoadGsInRax = '\x65\x48\x8b\x04\x25\x00\x00\x00\x00'
# inc rax
IncRax = '\x48\xff\xc0'
# int3
Int3 = '\xcc'

class PackedPhysicalMemory(object):
    '''The goal of this class is to provide a very simple GPA allocation policy.
    It basically packs up the physical space page by page.'''
    def __init__(self, BaseGpa = 0):
        self.Gpa = 0

    def GetGpa(self):
        '''Get the next available GPA address.'''
        Gpa = self.Gpa
        self.Gpa += 0x1000
        return Gpa

def CreatePartition(Pages, TebGva = 0):
    '''Create a partition and configure it like a Windows 64bit environment.'''
    PackedSpacePolicy = PackedPhysicalMemory()
    PartitionOptions = {
       'ProcessorCount' : 1,
       'Name' : '64b user'
    }

    Partition = hv.WHvPartition(**PartitionOptions)

    # Let's enable long mode now...
    # https://wiki.osdev.org/Setting_Up_Long_Mode.
    # We basically need several things (cf https://wiki.osdev.org/X86-64):
    #   * Set the PAE enable bit in CR4
    #   * Load CR3 with the physical address of the PML4
    #   * Enable long mode by setting the EFER.LME flag in MSR 0xC0000080
    #   * Enable paging

    # OK so we need to allocate memory for paging structures, and build the
    # virtual address space.
    Pml4Gpa = hv.BuildVirtualAddressSpace(
        Partition,
        Pages,
        PackedSpacePolicy
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
            hv.Cr0 : Cr0,
            hv.Cr3 : Cr3,
            hv.Cr4 : Cr4,
            hv.Efer : Efer,
        }
    )

    print 'Enabled 64-bit long mode'

    # We should be good to set-up 64-bit user-mode segments now.
    # 0:000> r @cs
    # cs=0033
    Cs = hv.Generate64bUserCodeSegment()
    # 0:001> r @ss
    # ss=002b
    DataSegment = hv.Generate64bUserDataSegment()
    # 0:001> r @fs
    # fs=0053
    TebSegment = hv.Generate64bUserDataSegment(TebGva)

    Partition.SetRegisters(
        0, {
            hv.Cs : Cs,
            hv.Ss : DataSegment,
            hv.Ds : DataSegment,
            hv.Es : DataSegment,
            hv.Fs : DataSegment,
            hv.Gs : TebSegment,
            #_Rdx : 0, XXX Figure out where the 806e9 is coming from.
        }
    )

    print 'Partition created:', Partition
    return Partition

class UserCode(unittest.TestCase):
    '''Test everything related to running long mode code.'''
    @classmethod
    def setUpClass(cls):
        '''This method is called once and initialize a partition object with a bunch
        of pages mapped in already.'''
        cls.TebGva = 0x000008b307ae000
        cls.CodeGva = 0x00007fffb8c05000
        cls.ReadOnlyGva = 0x00007fffb8c06000
        cls.ReadWriteGva = 0x00007fffb8c07000
        cls.ReadWriteExecuteGva = 0x00007fffb8c08000
        cls.KernelPageGva = 0xfffff80178e05000
        cls.Pages = [
            (cls.TebGva, 'rw'),
            (cls.CodeGva, 'rx'),
            (cls.ReadOnlyGva, 'r'),
            (cls.ReadWriteGva, 'rw'),
            (cls.KernelPageGva, 'rwx'),
        ]

        cls.Partition = CreatePartition(cls.Pages, cls.TebGva)
        cls.CodeHva = cls.Partition.TranslateGvaToHva(
            0,
            cls.CodeGva
        )

        cls.Snapshot = cls.Partition.Save()

    def setUp(self):
        '''Restore the context everytime before executing a test.'''
        self.Partition.Restore(self.Snapshot)

    def test_read_from_supervisor(self):
        '''Read from supervisor memory.'''
        Code = ReadMemory64(self.KernelPageGva) + Int3
        memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        ExitContext, _ = self.Partition.RunVp(0)
        VpException = ExitContext.VpException

        self.assertEqual(
            VpException.ExceptionType, hv.WHvX64ExceptionTypePageFault,
            'A PageFault exception(%x) is expected.' % VpException.ExceptionType
        )

        self.assertEqual(
            VpException.ErrorCode, 5, # XXX: Figure out the ErrorCode meaning.
            'The ErrorCode(%x) is expecting to show a write-access.' % VpException.ErrorCode,
        )

        self.assertEqual(
            VpException.ExceptionParameter, self.KernelPageGva,
            'The ExceptionParamter(%x) should be the GVA of the read-only page.' % VpException.ExceptionParameter
        )

    def test_execute_readonly(self):
        '''Execute read-only memory.'''
        Hva = self.Partition.TranslateGvaToHva(
            0,
            self.ReadOnlyGva
        )

        Content = IncRax + Int3
        memmove(Hva, Content, len(Content))

        self.Partition.SetRip(
            0,
            self.ReadOnlyGva
        )

        ExitContext, _ = self.Partition.RunVp(0)
        VpException = ExitContext.VpException
        hv.DumpExitContext(ExitContext)

        self.assertEqual(
            VpException.ExceptionType, hv.WHvX64ExceptionTypePageFault,
            'A PageFault exception(%x) is expected.' % VpException.ExceptionType
        )

        self.assertEqual(
            VpException.ErrorCode, 0x15, # XXX: Figure out the ErrorCode meaning.
            'The ErrorCode(%x) is expecting to show an execute-access.' % VpException.ErrorCode,
        )

        self.assertEqual(
            VpException.ExceptionParameter, self.ReadOnlyGva,
            'The ExceptionParamter(%x) should be the GVA of the read-only page.' % VpException.ExceptionParameter
        )

    def test_write_to_readonly(self):
        '''Write to read-only memory.'''
        Hva = self.Partition.TranslateGvaToHva(
            0,
            self.ReadOnlyGva
        )

        Value = 0xdeadbeefbaadc0de
        Content = struct.pack('<Q', Value)
        memmove(Hva, Content, len(Content))

        Code = WriteMemory64(self.ReadOnlyGva, Value) + Int3
        memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        ExitContext, _ = self.Partition.RunVp(0)
        VpException = ExitContext.VpException
        self.assertEqual(
            VpException.ExceptionType, hv.WHvX64ExceptionTypePageFault,
            'A PageFault exception(%x) is expected.' % VpException.ExceptionType
        )

        self.assertEqual(
            VpException.ErrorCode, 7, # XXX: Figure out the ErrorCode meaning.
            'The ErrorCode(%x) is expecting to show a write-access.' % VpException.ErrorCode,
        )

        self.assertEqual(
            VpException.ExceptionParameter, self.ReadOnlyGva,
            'The ExceptionParamter(%x) should be the GVA of the read-only page.' % VpException.ExceptionParameter
        )

    def test_read_from_readonly(self):
        '''Read from read-only memory.'''
        Hva = self.Partition.TranslateGvaToHva(
            0,
            self.ReadOnlyGva
        )

        Value = 0xdeadbeefbaadc0de
        Content = struct.pack('<Q', Value)
        memmove(Hva, Content, len(Content))

        Code = ReadMemory64(self.ReadOnlyGva) + Int3
        memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        ExitContext, _ = self.Partition.RunVp(0)
        Rax = self.Partition.GetRegister64(
            0,
            hv.Rax
        )

        self.assertEqual(
            Rax, Value,
            '@rax(%x) is supposed to have the expected value' % Rax
        )

    def test_read_from_gs(self):
        '''Read memory from the GS segment.'''
        TebHva = self.Partition.TranslateGvaToHva(
            0,
            self.TebGva
        )

        TebValue = 0xdeadbeefbaadc0de
        TebContent = struct.pack('<Q', TebValue)
        memmove(TebHva, TebContent, len(TebContent))

        Code = LoadGsInRax + Int3
        memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        ExitContext, _ = self.Partition.RunVp(0)
        Rax = self.Partition.GetRegister64(
            0,
            hv.Rax
        )

        self.assertEqual(
            Rax, TebValue,
            '@rax(%x) is supposed to have the expected Teb value' % Rax
        )

    def test_gva_translations(self):
        '''Run GVA translations on the partition.'''
        for Gva, _ in self.Pages:
            ResultCode, Gpa = self.Partition.TranslateGva(
                0,
                Gva
            )

            self.assertEqual(
                ResultCode.value, hv.WHvTranslateGvaResultSuccess,
                'TranslateGva(%x) returned %s.' % (Gpa, ResultCode)
            )

    def test_simple_user(self):
        '''Run a bunch of 'inc rax' followed by an 'int3' which we should get
        a VMEXIT for, and then step over and execute another 'inc rax' followed by
        an 'int3' and get one last VMEXIT.'''
        CodeGva = self.CodeGva

        N = 137
        Code  = ''
        # inc rax ; ... ; inc rax
        Code += IncRax * N
        # Compute the expected @rip at the first vmexit before we add the rest of the
        # code. This is used for testing everything is going as expected.
        ExpectedRip1 = CodeGva + len(Code)
        # int3. This is where the first vmexit we should get. We will skip over the
        # instruction and continue.
        Code += Int3
        Code += IncRax
        ExpectedRip2 = CodeGva + len(Code)
        # int3. This is the second vmexit we should get.
        Code += Int3

        memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            CodeGva
        )

        ExitContext, ExitReason = self.Partition.RunVp(0)
        Rip, Rax = self.Partition.GetRegisters64(
            0, (
                hv.Rip,
                hv.Rax
            )
        )

        ExpectedRax = N
        self.assertEqual(
            Rax, N,
            '@rax(%x) does not match the magic value.' % Rax
        )

        self.assertEqual(
            Rip, ExpectedRip1,
            '@rip(%x) does not match the end @rip.' % Rip
        )

        self.assertEqual(
            ExitReason.value, hv.WHvRunVpExitReasonException,
            'An exception VMEXIT is expected when the int3 is triggered.'
        )

        self.assertEqual(
            ExitContext.VpException.ExceptionType, hv.WHvX64ExceptionTypeBreakpointTrap,
            'A breakpoint exception is expected.'
        )

        VpContext = ExitContext.VpContext
        self.assertEqual(
            VpContext.InstructionLength, len(Int3),
            'The instruction length(%x) is supposed to be 1.' % VpContext.InstructionLength
        )

        # Successfully caught the first int3 interruption, stepping over it.
        self.Partition.SetRegisters(
            0, {
                hv.Rip : Rip + len(Int3)
            }
        )

        ExitContext, _ = self.Partition.RunVp(0)
        Rip, Rax = self.Partition.GetRegisters64(
            0, (
                hv.Rip,
                hv.Rax
            )
        )

        ExpectedRax += 1
        self.assertEqual(
            Rax, ExpectedRax,
            '@rax(%x) does not match the magic value.' % Rax
        )

        self.assertEqual(
            Rip, ExpectedRip2,
            '@rip(%x) does not match the end @rip.' % Rip
        )

        self.assertEqual(
            ExitReason.value, hv.WHvRunVpExitReasonException,
            'An exception VMEXIT is expected when the int3 is triggered.'
        )

        self.assertEqual(
            ExitContext.VpException.ExceptionType, hv.WHvX64ExceptionTypeBreakpointTrap,
            'A breakpoint exception is expected.'
        )

        VpContext = ExitContext.VpContext
        self.assertEqual(
            VpContext.InstructionLength, len(Int3),
            'The instruction length(%x) is supposed to be 1.' % VpContext.InstructionLength
        )

    def test_partition_counters(self):
        '''Check the WHvPartitionCounterSetMemory partition performance counter.'''
        MemoryCounters = self.Partition.GetPartitionCounters(
            hv.WHvPartitionCounterSetMemory
        )

        self.assertEqual(
            MemoryCounters.Mapped1GPageCount, 0,
            'There should not be any 1GB pages.'
        )

        self.assertEqual(
            MemoryCounters.Mapped2MPageCount, 0,
            'There should not be any 2MB pages.'
        )

        self.assertEqual(
            MemoryCounters.Mapped4KPageCount, 14,
            'There should be only 14 pages.'
        )

    def test_vp_counters(self):
        '''Check the processor performance counters.'''
        # XXX: They don't look right?
        pass

    def test_save_restore_registers(self):
        '''Take a snapshot modify registers and restore it.'''
        self.Partition.SetRegisters(
            0, {
                hv.Rax : 0xdeadbeefbaadc0de,
                hv.Rbx : 0xdeadbeefbaadc0de,
                hv.Rcx : 0xdeadbeefbaadc0de,
                hv.Rip : 0xdeadbeefbaadc0de,
                hv.Rsp : 0xdeadbeefbaadc0de
            }
        )

        Snapshot = self.Partition.Save()
        InitRax = self.Partition.GetRegister64(
            0,
            hv.Rax
        )

        self.Partition.SetRegisters(
            0, {
                hv.Rax : 0xaaaaaaaaaaaaaaaa
            }
        )

        self.Partition.Restore(Snapshot)
        Rax = self.Partition.GetRegister64(
            0,
            hv.Rax
        )

        self.assertEqual(
            Rax, InitRax,
            '@rax(%x) does not match the value it had before the snapshot.' % Rax
        )

def main(argc, argv):
    HypervisorPresent = hv.IsHypervisorPresent()
    print 'HypervisorPresent:', HypervisorPresent
    if not HypervisorPresent:
        return 1

    unittest.main(verbosity = 2)
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))

