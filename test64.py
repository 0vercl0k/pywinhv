# Axel '0vercl0k' Souchet - February 7th 2019
import pywinhv as hv
import sys
import struct
import unittest
import ctypes as ct

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

    def GetGpa(self, Pages = 1):
        '''Get the next available GPA address.'''
        Gpa = self.Gpa
        self.Gpa += (0x1000 * Pages)
        return Gpa

def CreatePartition(Pages, PackedSpacePolicy, TebGva):
    '''Create a partition and configure it like a Windows 64bit environment.'''
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

# https://wiki.osdev.org/Exceptions#Page_Fault
PF_ERRCODE_PRESENT = 1 << 0
PF_ERRCODE_WRITE = 1 << 1
PF_ERRCODE_USER = 1 << 2
PF_ERRCODE_RESERVED_WRITE = 1 << 3
PF_ERRCODE_IFETCH = 1 << 4

class FeatureTests(unittest.TestCase):
    '''Test everything related to features.'''
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
        cls.Page0Gva = 0x0007ff60cf10000
        cls.Page1Gva = 0x0007ff60cf11000
        cls.Pages = [
            (cls.TebGva, 'rw'),
            (cls.CodeGva, 'rx'),
            (cls.ReadOnlyGva, 'r'),
            (cls.ReadWriteGva, 'rw'),
            (cls.KernelPageGva, 'rwx'),
            # Those VAs have the same PTE, and used to trigger a bug in the
            # page table generation.
            # PML4E=255, PDPTE=485, PDE=310, PTE=353.
            (0x00007ff966d61000, 'r'),
            # PML4E=255, PDPTE=485, PDE=337, PTE=353.
            (0x00007ff96a361000, 'r'),
            # PML4E=255, PDPTE=309, PDE=172, PTE=353
            (0x0000014d55961000, 'r'),
            # The goal with these is to have 2 contiguous pages in the virtual
            # space but not in the host virtual space.
            (cls.Page0Gva, 'r'),
            (cls.Page1Gva, 'r')
        ]

        cls.Policy = PackedPhysicalMemory()
        cls.Partition = CreatePartition(cls.Pages, cls.Policy, cls.TebGva)
        TranslationResult, cls.CodeHva = cls.Partition.TranslateGvaToHva(
            0,
            cls.CodeGva
        )

        assert TranslationResult.value == hv.WHvTranslateGvaResultSuccess, 'The GVA->HVA translation should be a success'

        cls.Snapshot = cls.Partition.Save()

    def setUp(self):
        '''Restore the context everytime before executing a test.'''
        self.Partition.Restore(self.Snapshot)

    def test_readwrite_unmapped(self):
        '''Read from / to unmapped GVA.'''
        self.assertFalse(self.Partition.WriteGva(
                0,
                0,
                'hello'
            ), 'The write to unmapped memory should fail.'
        )

        self.assertIsNone(self.Partition.ReadGva(
                0,
                0,
                0x1000
            ), 'The read to unmapped memory should fail.'
        )

    def test_writegva_cross_pages(self):
        '''Read from and write to GVA space across two pages that are not contiguous
        in the host virtual space.'''
        TranslationResult, Hva0 = self.Partition.TranslateGvaToHva(
            0,
            self.Page0Gva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The translation should succeed.'
        )

        self.assertIsNotNone(Hva0, 'The GVA->HVA translation should succeed.')

        TranslationResult, Hva1 = self.Partition.TranslateGvaToHva(
            0,
            self.Page1Gva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The translation should succeed.'
        )

        self.assertIsNotNone(Hva1, 'The GVA->HVA translation should succeed.')

        self.assertNotEqual(
            abs(Hva1 - Hva0), 0x1000,
            'The two pages should not be contiguous in host virtual space.'
        )

        Content = 'hello friends!'
        EndOffset = 0xff8
        Address = self.Page0Gva + EndOffset
        self.assertTrue(self.Partition.WriteGva(
            0,
            Address,
            Content
        ))

        # The first 8 bytes are at the end of the first page.
        First = ct.string_at(Hva0 + EndOffset, 8)
        # The last 6 bytes are at the beginning of the second page.
        Second = ct.string_at(Hva1, 6)

        self.assertEqual(
            First + Second, Content,
            'The first and second bit should match the content.'
        )

        ReadContent = self.Partition.ReadGva(
            0,
            self.Page0Gva + EndOffset,
            len(Content)
        )

        self.assertEqual(
            ReadContent, Content,
            'The content should match.'
        )

    def test_snapshot_only_writeable(self):
        '''Ensure that the snapshot only restores / track pages that are writeable.'''
        ByteSaved = self.Partition.ReadGva(
            0,
            self.ReadOnlyGva,
            1
        )

        self.assertIsNotNone(ByteSaved, 'The ByteSaved should not be None.')
        Snapshot = self.Partition.Save()

        self.assertTrue(self.Partition.WriteGva(
                0,
                self.ReadOnlyGva,
                '\xAA'
            ),
            'The write should succeed.'
        )

        self.Partition.Restore(Snapshot)

        ByteRead = self.Partition.ReadGva(
            0,
            self.ReadOnlyGva,
            1
        )

        self.assertNotEqual(
            ByteSaved, ByteRead,
            'The two bytes should match up.'
        )

        # Restore the orginal byte as it will never get its original value back
        # otherwise.
        self.assertTrue(self.Partition.WriteGva(
                0,
                self.ReadOnlyGva,
                ByteSaved
            ),
            'The write should succeed.'
        )

    def test_mapregion_translategpa(self):
        '''Map a GPA range bigger than 0x1000 and ensure the GPA->HVA translation works
        on every page of the region.'''
        RegionSize = 5
        RegionGpa = self.Policy.GetGpa(5)
        HvaBase, SizeInBytes = self.Partition.MapGpaRange(
            RegionGpa,
            'hello',
            'r'
        )

        for Offset in range(0, SizeInBytes, 0x1000):
            CurHva = self.Partition.TranslateGpa(RegionGpa + Offset)
            self.assertEqual(
                CurHva, HvaBase + Offset,
                'The two HVAs should match.'
            )

    def test_translate_gva_with_permcheck_kern(self):
        '''Translate a GVA->GPA and validate page permissions against a kernl page.'''
        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.KernelPageGva,
            'r'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The kernel page should not be readable from cpl3.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.KernelPageGva,
            're'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The kernel page should be translatable from cpl3 with PrivilegeExempt.'
        )

    def test_translate_gva_with_permcheck_rx(self):
        '''Translate a GVA->GPA and validate page permissions against a rx page.'''
        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'r'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The code page should be marked as readable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'w'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The code page page should not be marked as writeable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'x'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The code page should be marked as executable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'rx'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The code page should be marked as rw in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'rwx'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The code page should not be marked as rwx in the page tables.'
        )

    def test_translate_gva_with_permcheck_rx(self):
        '''Translate a GVA->GPA and validate page permissions against a rx page.'''
        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'r'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The code page should be marked as readable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'w'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The code page page should not be marked as writeable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'x'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The code page should be marked as executable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'rx'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The code page should be marked as rw in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.CodeGva,
            'rwx'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The code page should not be marked as rwx in the page tables.'
        )

    def test_translate_gva_with_permcheck_ro(self):
        '''Translate a GVA->GPA and validate page permissions against a read-only
        page.'''
        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.ReadOnlyGva,
            'r'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The read-only page should be marked as readable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.ReadOnlyGva,
            'w'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The read-only page should not be marked as writeable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.ReadOnlyGva,
            'x'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The read-only page should not be marked as executable in the page tables.'
        )

        TranslationResult, _ = self.Partition.TranslateGva(
            0,
            self.ReadOnlyGva,
            'xe'
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultPrivilegeViolation,
            'The translation should still return a PrivilegeViolation even with WHvTranslateGvaFlagPrivilegeExempt.'
        )

    def test_clear_dirty_pages(self):
        '''Clear the dirty bits of the pages.'''
        Code = WriteMemory64(self.TebGva, 1) + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        self.Partition.RunVp(0)

        DirtyGpas = self.Partition.QueryGpaRangeDirtyPages(
            0,
            len(self.Partition.TranslationTable) * 0x1000
        )

        TranslationResult, TebGpa = self.Partition.TranslateGva(
            0,
            self.TebGva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The TEB GVA->GPA translation result (%s) must be a success.' % TranslationResult
        )

        self.assertEqual(
            TebGpa in DirtyGpas, True,
            'The TEB GPA should be dirty.'
        )

        self.Partition.ClearGpaRangeDirtyPages(
            0,
            len(self.Partition.TranslationTable) * 0x1000
        )

        Bits = self.Partition.QueryGpaRangeDirtyBitmap(
            0,
            len(self.Partition.TranslationTable) * 0x1000
        )

        for Bit in Bits:
            self.assertEqual(
                Bit, 0,
                'Bit(%x) is expected to be cleared.' % Bit
            )

    def test_number_dirty_pages(self):
        '''Count the number of bits returned for dirty pages.'''
        Bits = self.Partition.QueryGpaRangeDirtyBitmap(
            0,
            len(self.Partition.TranslationTable) * 0x1000
        )

        self.assertEqual(
            len(Bits), len(self.Partition.TranslationTable),
            'The number of bits(%x) has to match the number of physical pages.' % len(Bits)
        )

    def test_read_from_noncanonical(self):
        '''Read from a non canonical page.'''
        NonCanonicalGva = 0xdeadbeefbaadc0de
        Code = ReadMemory64(NonCanonicalGva)
        ct.memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        ExitContext, _ = self.Partition.RunVp(0)
        VpException = ExitContext.VpException

        self.assertEqual(
            VpException.ExceptionType, hv.WHvX64ExceptionTypeGeneralProtectionFault,
            'A GeneralProtection exception(%x) is expected.' % VpException.ExceptionType
        )

        self.assertEqual(
            # Error code: The General Protection Fault sets an error code,
            # which is the segment selector index when the exception is segment related.
            # Otherwise, 0.
            VpException.ErrorCode, 0,
            'The ErrorCode(%x) is expected to be 0.' % VpException.ErrorCode,
        )

    def test_read_from_nonpresent(self):
        '''Read from a non-present page.'''
        NonPresentGva = 1337
        Code = ReadMemory64(NonPresentGva)
        ct.memmove(self.CodeHva, Code, len(Code))
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
            VpException.ErrorCode,
            PF_ERRCODE_USER,
            'The ErrorCode(%x) is expecting to show a read-access from non present GVA.' % VpException.ErrorCode,
        )

        self.assertEqual(
            VpException.ExceptionParameter, NonPresentGva,
            'The ExceptionParameter(%x) should be the GVA of the non-present page.' % VpException.ExceptionParameter
        )

    def test_read_from_supervisor(self):
        '''Read from supervisor memory.'''
        Code = ReadMemory64(self.KernelPageGva) + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
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
            VpException.ErrorCode,
            PF_ERRCODE_PRESENT | PF_ERRCODE_USER,
            'The ErrorCode(%x) is expecting to show a write-access.' % VpException.ErrorCode,
        )

        self.assertEqual(
            VpException.ExceptionParameter, self.KernelPageGva,
            'The ExceptionParameter(%x) should be the GVA of the read-only page.' % VpException.ExceptionParameter
        )

    def test_execute_readonly(self):
        '''Execute read-only memory.'''
        TranslationResult, Hva = self.Partition.TranslateGvaToHva(
            0,
            self.ReadOnlyGva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The GVA->HVA translation should be a success.'
        )

        Content = IncRax + Int3
        ct.memmove(Hva, Content, len(Content))

        self.Partition.SetRip(
            0,
            self.ReadOnlyGva
        )

        ExitContext, _ = self.Partition.RunVp(0)
        VpException = ExitContext.VpException

        self.assertEqual(
            VpException.ExceptionType, hv.WHvX64ExceptionTypePageFault,
            'A PageFault exception(%x) is expected.' % VpException.ExceptionType
        )

        self.assertEqual(
            VpException.ErrorCode,
            PF_ERRCODE_PRESENT | PF_ERRCODE_USER | PF_ERRCODE_IFETCH,
            'The ErrorCode(%x) is expecting to show an execute-access.' % VpException.ErrorCode,
        )

        self.assertEqual(
            VpException.ExceptionParameter, self.ReadOnlyGva,
            'The ExceptionParameter(%x) should be the GVA of the read-only page.' % VpException.ExceptionParameter
        )

    def test_write_to_readonly(self):
        '''Write to read-only memory.'''
        TranslationResult, Hva = self.Partition.TranslateGvaToHva(
            0,
            self.ReadOnlyGva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The GVA->HVA translation should be a success.'
        )

        Value = 0xdeadbeefbaadc0de
        Content = struct.pack('<Q', Value)
        ct.memmove(Hva, Content, len(Content))

        Code = WriteMemory64(self.ReadOnlyGva, Value) + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
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
            VpException.ErrorCode,
            PF_ERRCODE_PRESENT | PF_ERRCODE_USER | PF_ERRCODE_WRITE,
            'The ErrorCode(%x) is expecting to show a write-access.' % VpException.ErrorCode,
        )

        self.assertEqual(
            VpException.ExceptionParameter, self.ReadOnlyGva,
            'The ExceptionParameter(%x) should be the GVA of the read-only page.' % VpException.ExceptionParameter
        )

    def test_read_from_readonly(self):
        '''Read from read-only memory.'''
        TranslationResult, Hva = self.Partition.TranslateGvaToHva(
            0,
            self.ReadOnlyGva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The GVA->HVA translation should be a success.'
        )

        Value = 0xdeadbeefbaadc0de
        Content = struct.pack('<Q', Value)
        ct.memmove(Hva, Content, len(Content))

        Code = ReadMemory64(self.ReadOnlyGva) + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
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
        TranslationResult, TebHva = self.Partition.TranslateGvaToHva(
            0,
            self.TebGva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The GVA->HVA translation should be a success.'
        )

        TebValue = 0xdeadbeefbaadc0de
        TebContent = struct.pack('<Q', TebValue)
        ct.memmove(TebHva, TebContent, len(TebContent))

        Code = LoadGsInRax + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
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
        Gpas = []
        for Gva, _ in self.Pages:
            ResultCode, Gpa = self.Partition.TranslateGva(
                0,
                Gva
            )

            self.assertEqual(
                ResultCode.value, hv.WHvTranslateGvaResultSuccess,
                'TranslateGva(%x) returned %s.' % (Gpa, ResultCode)
            )

            Gpas.append(Gva)

        self.assertEqual(
            len(set(Gpas)), len(Gpas),
            'Every GVA should map to a unique GPA'
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

        ct.memmove(self.CodeHva, Code, len(Code))
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
        self.Partition.SetRip(0, Rip + len(Int3))

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

        PageCount = 24
        self.assertGreaterEqual(
            MemoryCounters.Mapped4KPageCount, PageCount,
            'There should be only > %d pages.' % PageCount
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

        self.Partition.SetRegister(0, hv.Rax, 0xaaaaaaaaaaaaaaaa)

        self.Partition.Restore(Snapshot)
        Rax = self.Partition.GetRegister64(
            0,
            hv.Rax
        )

        self.assertEqual(
            Rax, InitRax,
            '@rax(%x) does not match the value it had before the snapshot.' % Rax
        )

    def test_save_restore_memory(self):
        '''Take a snapshot modify memory and resore it.'''
        TranslationResult, TebHva = self.Partition.TranslateGvaToHva(
            0,
            self.TebGva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The GVA->HVA translation should be a success.'
        )

        TebContent = '\xaa' * 0x1000
        ct.memmove(TebHva, TebContent, len(TebContent))

        Snapshot = self.Partition.Save()
        TebContent = '\xbb' * 0x1000
        ct.memmove(TebHva, TebContent, len(TebContent))

        self.Partition.Restore(Snapshot)

        Code = ReadMemory64(self.TebGva) + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        self.Partition.RunVp(0)
        Rax = self.Partition.GetRegister64(
            0,
            hv.Rax
        )

        self.assertEqual(
            Rax, 0xaaaaaaaaaaaaaaaa,
            '@rax(%x) is supposed to have the value restored by the snapshot.' % Rax
        )

    def test_save_restore_gpa_to_hva(self):
        '''Ensure that the translation table is saved in a snapshot.'''
        TranslationTable = self.Partition.GetTranslationTable()
        Snapshot = self.Partition.Save()
        PageGpa = self.Policy.GetGpa()
        Hva, Size = self.Partition.MapGpaRange(
            PageGpa,
            'hello',
            'r'
        )

        self.assertEqual(
            Size, 0x1000,
            'The size(%x) is expected to be a page large.' % Size
        )

        self.assertEqual(
            PageGpa in self.Partition.TranslationTable, True,
            'The GPA(%x) is expected to be added to the translation table.' % PageGpa
        )

        self.assertEqual(
            self.Partition.TranslationTable != TranslationTable,
            True,
            'The translation tables are expected to be different.'
        )

        self.Partition.Restore(Snapshot)

        self.assertEqual(
            PageGpa not in self.Partition.TranslationTable, True,
            'The GPA(%x) is expected to not be in the translation table anymore.' % PageGpa
        )

        self.Partition.UnmapGpaRange(
            PageGpa,
            0x1000,
            Hva
        )

        self.assertEqual(
            self.Partition.TranslationTable, TranslationTable,
            'The translation tables are expected to be different.'
        )

    def test_save_restore_dirty_pages(self):
        '''Ensure that a dirty page is turned non dirty after a snapshot. Also ensure
        that on restore it keeps non dirty.'''
        # Let's make sure the TEB page is clean.
        TranslationResult, TebGpa = self.Partition.TranslateGva(
            0,
            self.TebGva
        )

        self.assertEqual(
            TranslationResult.value,
            hv.WHvTranslateGvaResultSuccess,
            'The TEB GVA->GPA translation result(%s) must be a success.' % TranslationResult
        )

        Dirty = self.Partition.IsGpaDirty(TebGpa)

        self.assertEqual(
            Dirty, False,
            'The TEB page is expected to be clean.'
        )

        # Dirty the TEB page.
        Code = WriteMemory64(self.TebGva, 1) + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        self.Partition.RunVp(0)

        # Ensure the page is dirty.
        Dirty = self.Partition.IsGpaDirty(TebGpa)

        self.assertEqual(
            Dirty, True,
            'The TEB page is expected to be dirty.'
        )

        # Grab a snapshot.
        Snapshot = self.Partition.Save()

        # Make sure the page is clean again.
        Dirty = self.Partition.IsGpaDirty(TebGpa)

        self.assertEqual(
            Dirty, False,
            'The TEB page is expected to be clean after snapshot.'
        )

        # Dirty the TEB page.
        Code = WriteMemory64(self.TebGva, 1) + Int3
        ct.memmove(self.CodeHva, Code, len(Code))
        self.Partition.SetRip(
            0,
            self.CodeGva
        )

        self.Partition.RunVp(0)

        # Ensure the page is dirty.
        Dirty = self.Partition.IsGpaDirty(TebGpa)

        self.assertEqual(
            Dirty, True,
            'The TEB page is expected to be dirty.'
        )

        # Restore the snapshot.
        self.Partition.Restore(Snapshot)

        # Ensure the page is back clear again.
        Dirty = self.Partition.IsGpaDirty(TebGpa)

        self.assertEqual(
            Dirty, False,
            'The TEB page is expected to be clean after restore.'
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

