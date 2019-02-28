# Axel '0vercl0k' Souchet - February 25th 2019
import winhvplatform as hvplat
import pywinhv as whv
import utils

import ctypes as ct
import sys

class WHvVirtualProcessor(object):
    '''This is an abstraction around Virtual Processors. It is useful to split the logic
    between the partition and the VPs as it feels more natural to program. No need to
    remember the VP id, etc.'''
    def __init__(self, Handle, Partition, VpIndex):
        self.Handle = Handle
        self.Partition = Partition
        self.VpIndex = VpIndex

    def SetRegisters(self, Registers):
        '''Set registers in a VP.'''
        Success, Ret = hvplat.WHvSetVirtualProcessorRegisters(
            self.Handle,
            self.Index,
            Registers
        )

        assert Success, 'WHvSetVirtualProcessorRegisters failed with: %s.' % hvplat.WHvReturn(Ret)

    @property
    def Index(self):
        '''Get the VP index.'''
        return self.VpIndex

    def SetRegister(self, Register, Value):
        '''Set a register of a VP.'''
        return self.SetRegisters({
            Register : Value
        })

    def SetRip(self, Rip):
        '''Set the @rip register of a VP.'''
        return self.SetRegister(
            hvplat.Rip,
            Rip
        )

    def GetRegisters(self, *Registers):
        '''Get registers of a VP.'''
        if isinstance(Registers[0], (tuple, list)):
            # This is probably the case where GetRegisters is invoked with an
            # array directly. It is useful at times, so we handle this case.
            Registers = Registers[0]

        Success, Registers, Ret = hvplat.WHvGetVirtualProcessorRegisters(
            self.Handle,
            self.Index,
            Registers
        )

        assert Success, 'GetRegisters failed with: %s.' % hvplat.WHvReturn(Ret)
        return Registers

    def GetRegisters64(self, *Registers):
        '''Get VP registers and return the .Reg64 part.'''
        Registers = self.GetRegisters(*Registers)
        Registers = map(
            lambda R: R.Reg64,
            Registers
        )

        return Registers

    def GetRegister(self, Register):
        '''Get a single VP register.'''
        return self.GetRegisters(Register)[0]

    def GetRegister64(self, Register):
        '''Get a VP register.'''
        return self.GetRegister(Register).Reg64

    def GetRip(self):
        '''Get the @rip register of a VP.'''
        return self.GetRegister64(hvplat.Rip)

    def DumpRegisters(self):
        '''Dump the register of a VP.'''
        R = self.GetRegisters(
            hvplat.Rax, hvplat.Rbx, hvplat.Rcx, hvplat.Rdx, hvplat.Rsi, hvplat.Rdi,
            hvplat.Rip, hvplat.Rsp, hvplat.Rbp, hvplat.R8, hvplat.R9, hvplat.R10,
            hvplat.R11, hvplat.R12, hvplat.R13, hvplat.R14, hvplat.R15,
            hvplat.Cs, hvplat.Ss, hvplat.Ds, hvplat.Es, hvplat.Fs, hvplat.Gs,
            hvplat.Rflags, hvplat.Cr3
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
        TranslationResult, Hva = self.TranslateGvaToHva(Rip)

        if TranslationResult.value == whv.WHvTranslateGvaResultSuccess and Hva is not None:
            HowManyLeft = 0x1000 - (Hva & 0xfff)
            HowMany = min(HowManyLeft, 16)
            Code = ct.string_at(Hva, HowMany).encode('hex')

        print '%016x' % Rip, Code

    def GetVpCounters(self, Counter):
        '''Get a virtual processor performance counter.'''
        Success, Counters, Ret = hvplat.WHvGetVirtualProcessorCounters(
            self.Handle,
            self.Index,
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

    def Run(self):
        '''Run the virtual processor.'''
        Success, ExitContext, Ret = hvplat.WHvRunVirtualProcessor(
            self.Handle,
            self.Index
        )

        assert Success, 'WHvRunVirtualProcessor failed with: %s.' % hvplat.WHvReturn(Ret)
        return ExitContext, hvplat.WHvExitReason(ExitContext.ExitReason)

    def TranslateGva(self, Gva, Flags = None):
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
            self.Index,
            Gva,
            WHvFlags
        )

        assert Success, 'WHvTranslateGva failed with: %s.' % hvplat.WHvReturn(Ret)
        return (hvplat.WHvTranslateGvaResultCode(ResultCode), Gpa)

    def TranslateGvaToHva(self, Gva, Flags = None):
        '''Translate a GVA to an HVA. This combines TranslateGva / TranslateGpa to
        go from a GVA to an HVA.'''
        GvaAligned, Offset = utils.SplitAddress(Gva)
        TranslationResult, Gpa = self.TranslateGva(
            GvaAligned,
            Flags
        )

        if TranslationResult.value != whv.WHvTranslateGvaResultSuccess:
            return TranslationResult, None

        Hva = self.Partition.TranslateGpa(Gpa)
        if Hva is None:
            return TranslationResult, None

        return TranslationResult, Hva + Offset

    def ReadGva(self, Gva, Size):
        '''Read directly from a GVA.'''
        Content = ''
        while Size > 0:
            TranslationResult, Hva = self.TranslateGvaToHva(
                Gva,
                'r'
            )

            if TranslationResult.value != whv.WHvTranslateGvaResultSuccess or Hva is None:
                return None

            # Compute how many bytes we can write in this page.
            _, GvaOffset = utils.SplitAddress(Gva)
            HowManyBytesWriteable = 0x1000 - GvaOffset
            # Compute the amount of byte we actually want to write.
            # If we have more content than what's left in this page, we fill
            # the page and move the cursor forward.
            # If we have more space than content, then we just write the rest of the
            # content we have and we are done.
            HowMany = min(
                HowManyBytesWriteable,
                Size
            )

            Content += ct.string_at(Hva, HowMany)
            Size -= HowMany
            Gva += HowMany

        return Content

    def WriteGva(self, Gva, Content, Force = False):
        '''Write directly to a GVA.'''
        Size = len(Content)
        Hvas = []
        Flags = 'w'

        # If the user asks us to not do permission checking then we won't do any.
        if Force:
            # We don't use the 'e' flag for privilege exemption because it still
            # will not allow us to write in read-only memory for example.
            Flags = None

        # First step is to ensure that all the translation works out. We populate a list
        # of work to do if everything goes well.
        while Size > 0:
            TranslationResult, Hva = self.TranslateGvaToHva(
                Gva,
                Flags
            )

            if TranslationResult.value != whv.WHvTranslateGvaResultSuccess or Hva is None:
                return False


            # Compute how many bytes we can write in this page.
            _, GvaOffset = utils.SplitAddress(Gva)
            HowManyBytesWriteable = 0x1000 - GvaOffset
            # Compute the amount of byte we actually want to write.
            # If we have more content than what's left in this page, we fill
            # the page and move the cursor forward.
            # If we have more space than content, then we just write the rest of the
            # content we have and we are done.
            HowMany = min(
                HowManyBytesWriteable,
                Size
            )

            Hvas.append((Hva, HowMany))
            Size -= HowMany
            Gva += HowMany

        # Once we verified all the pages in the region exist, let's
        # write the data.
        for Hva, HowMany in Hvas:
            # Write the content to the HVA and slice Content.
            ct.memmove(Hva, Content, HowMany)
            Content = Content[HowMany:]

        return True

def main(argc, argv):
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))

