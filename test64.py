# Axel '0vercl0k' Souchet - February 7th 2019
import pywinhv as hv
from ctypes import memmove
import sys

def main(argc, argv):
    HypervisorPresent = hv.IsHypervisorPresent()
    print 'HypervisorPresent:', HypervisorPresent
    if not HypervisorPresent:
        return 1

    print '64-bit kernel'.center(80, '=')

    PartitionOptions = {
       'ProcessorCount' : 1,
       'Name' : '64b user'
    }


    with hv.WHvPartition(**PartitionOptions) as Partition:
        print 'Partition created:', Partition


        # Let's enable long mode now...
        # https://wiki.osdev.org/Setting_Up_Long_Mode.
        # We basically need several things (cf https://wiki.osdev.org/X86-64):
        #   * Set the PAE enable bit in CR4
        #   * Load CR3 with the physical address of the PML4
        #   * Enable long mode by setting the EFER.LME flag in MSR 0xC0000080
        #   * Enable paging

        # OK so we need to allocate memory for paging structures, and build the
        # virtual address space.
        IdtGva = 0xfffff803dc545000
        Pages = [
            0x00007fffb8c05000,
            0x00007fffb8c06000,
            0x00007fffb8c07000,
            0x00007ff746a40000,
            IdtGva
        ]

        PagingBase = Partition.GetGpa()
        Pml4Gpa = hv.BuildVirtualAddressSpace(
            Partition,
            Pages
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
                hv.Rflags : 0x202
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
        TebSegment = hv.Generate64bUserDataSegment(Pages[1], 0x2b)

        # XXX: Configure GS.
        Partition.SetRegisters(
            0, {
                hv.Cs : Cs,
                hv.Ss : DataSegment,
                hv.Ds : DataSegment,
                hv.Es : DataSegment,
                hv.Fs : DataSegment,
                #_Gs : TebSegment,
                #_Rdx : 0, XXX Figure out where the 806e9 is coming from.
            }
        )

        for Gva in Pages:
            ResultCode, Gpa = Partition.TranslateGva(
                0,
                Gva
            )
            print 'GVA: %016x translated to GPA: %016x' % (Gva, Gpa)
            assert ResultCode.value == hv.WHvTranslateGvaResultSuccess, 'TranslateGva(%x) returned %s.' % (Gpa, ResultCode)

        print 'GVA->GPA translations worked!'

        # Configure an IDT.
        # Configure the base of the IDT where we don't have any memory mapped.
        # This allow us to trigger a memory access violation when it is read.
        Idtr = Partition.GetRegister(0, hv.Idtr)
        print hex(Idtr.Table.Base), hex(Idtr.Table.Limit)
        Idtr.Table.Base = IdtGva
        Idtr.Table.Limit = 0
        Partition.SetRegisters(0, {
                hv.Idtr : Idtr,
            }
        )
        Idtr = Partition.GetRegister(0, hv.Idtr)
        print hex(Idtr.Table.Base), hex(Idtr.Table.Limit)

        IdtHva = Partition.TranslateGvaToHva(
            0,
            Idtr.Table.Base
        )

        print 'IDT base is at HVA:%016x' % IdtHva
        IdtContent = ('\xaa\xbb\x33\x00\x00' + chr(0b10001110) + '\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00') * 256
        memmove(IdtHva, IdtContent, len(IdtContent))

        # Go write initialize it with some code.
        CodeHva = Partition.TranslateGvaToHva(
            0,
            Pages[0]
        )

        print 'Translated GVA:%x to HVA:%x' % (Pages[0], CodeHva)
        Code = '\x48\xff\xc0' * 137 + '\xcc'
        #Code =  '\x48\xff\xc0' * 1 + '\xcc'
        memmove(CodeHva, Code, len(Code))
        Partition.SetRip(
            0,
            Pages[0]
        )

        ExitContext = Partition.RunVp(0)
        Partition.DumpRegisters(0)

        ExitReason = hv.WHvExitReason(ExitContext.ExitReason)
        print 'Partition exited with:', ExitReason
        hv.DumpExitContext(ExitContext)
        Rip, Rax = Partition.GetRegisters64(
            0, (
                hv.Rip,
                hv.Rax
            )
        )

        assert Rax == 137, '@rax(%x) does not match the magic value.' % Rax
        assert Rip == (Pages[0] + (137 * 3)), '@rip(%x) does not match the end @rip.' % Rip
        # XXX: We want an actual memory violation when reading IDT.
        assert ExitReason.value == hv.WHvRunVpExitReasonUnrecoverableException, 'A memory fault is expected when the int3 is triggered as the IDTR.Base is unmapped.'

    print 'All good!'
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))

