import idc
import idautils


for funcea in idautils.Functions():
    for (startea, endea) in idautils.Chunks(funcea):
        for head in idautils.Heads(startea, endea):
            pointer = head
            if idc.print_insn_mnem(pointer) == 'syscall':
                print('{} | {}'.format(hex(pointer), idc.GetDisasm(pointer)))