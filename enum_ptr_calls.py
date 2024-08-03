import idc
import idautils


for funcea in idautils.Functions():
    for (startea, endea) in idautils.Chunks(funcea):
        for head in idautils.Heads(startea, endea):
            pointer = head
            if idc.print_insn_mnem(pointer) == 'call':
                op_type = idc.get_operand_type(pointer, 0)
                if op_type in (idc.o_reg, idc.o_phrase, idc.o_displ):
                    print('{} | {}'.format(hex(pointer), idc.GetDisasm(pointer)))