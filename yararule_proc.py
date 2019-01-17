from idc import *
from idaapi import *
import idautils

YARA_OPERAND_SIZE = 8
YARA_RELOCATION_NULL_MAGIC = 0xfffaBADA
YARA_RELOCATION_END_MAGIC = 0xffffFFFF


def read_qw(self, insn, eaoffset):
    qw = get_qword(insn.ea+eaoffset)
    eaoffset += 8
    return SIGNEXT(qw, 64), eaoffset


opcodes = [
    ('OP_ADD_M', 32, CF_USE1, [
     {'value': read_qw, 'dtyp': dt_qword, 'type': o_imm}]),
    ('OP_AND', 1, 0, []),
    ('OP_BITWISE_AND', 5, 0, []),
    ('OP_BITWISE_NOT', 4, 0, []),
    ('OP_BITWISE_OR', 6, 0, []),
    ('OP_BITWISE_XOR', 7, 0, []),
    ('OP_CALL', 15, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_string, 'type': o_mem}]),
    ('OP_CLEAR_M', 31, CF_USE1, [
     {'value': read_qw, 'dtyp': dt_qword, 'type': o_imm}]),
    ('OP_CONTAINS', 40, 0, []),
    ('OP_COUNT', 20, 0, []),
    ('OP_DBL_ADD', 126, 0, []),
    ('OP_DBL_DIV', 129, 0, []),
    ('OP_DBL_EQ', 120, 0, []),
    ('OP_DBL_GE', 125, 0, []),
    ('OP_DBL_GT', 123, 0, []),
    ('OP_DBL_LE', 124, 0, []),
    ('OP_DBL_LT', 122, 0, []),
    ('OP_DBL_MINUS', 130, 0, []),
    ('OP_DBL_MUL', 128, 0, []),
    ('OP_DBL_NEQ', 121, 0, []),
    ('OP_DBL_SUB', 127, 0, []),
    ('OP_ENTRYPOINT', 39, 0, []),
    ('OP_ERROR', 0, 0, []),
    ('OP_FILESIZE', 38, 0, []),
    ('OP_FOUND', 22, 0, []),
    ('OP_FOUND_AT', 23, 0, []),
    ('OP_FOUND_IN', 24, 0, []),
    ('OP_HALT', 255, CF_STOP, []),
    ('OP_IMPORT', 42, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_string, 'type': o_mem}]),
    ('OP_INCR_M', 30, CF_USE1, []),
    ('OP_INDEX_ARRAY', 19, 0, []),
    ('OP_INIT_RULE', 28, CF_USE1 | CF_USE2, [{'addr': read_qw, 'dtyp': dt_qword, 'type': o_mem}, {
     'addr': read_qw, 'dtyp': dt_qword, 'type': o_near}]),
    ('OP_INT16', 241, 0, []),
    ('OP_INT16BE', 247, 0, []),
    ('OP_INT32', 242, 0, []),
    ('OP_INT32BE', 248, 0, []),
    ('OP_INT8', 240, 0, []),
    ('OP_INT8BE', 246, 0, []),
    ('OP_INT_ADD', 106, 0, []),
    ('OP_INT_DIV', 109, 0, []),
    ('OP_INT_EQ', 100, 0, []),
    ('OP_INT_GE', 105, 0, []),
    ('OP_INT_GT', 103, 0, []),
    ('OP_INT_LE', 104, 0, []),
    ('OP_INT_LT', 102, 0, []),
    ('OP_INT_MINUS', 110, 0, []),
    ('OP_INT_MUL', 108, 0, []),
    ('OP_INT_NEQ', 101, 0, []),
    ('OP_INT_SUB', 107, 0, []),
    ('OP_INT_TO_DBL', 11, CF_USE1, [
     {'value': read_qw, 'dtyp': dt_qword, 'type': o_imm}]),
    ('OP_JFALSE', 44, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_qword, 'type': o_near}]),
    ('OP_JLE', 37, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_qword, 'type': o_near}]),
    ('OP_JNUNDEF', 36, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_qword, 'type': o_near}]),
    ('OP_JTRUE', 45, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_qword, 'type': o_near}]),
    ('OP_LENGTH', 21, 0, []),
    ('OP_LOOKUP_DICT', 43, 0, []),
    ('OP_MATCHES', 41, 0, []),
    ('OP_MATCH_RULE', 29, CF_USE1, [{
     'addr': read_qw, 'dtyp': dt_qword, 'type': o_mem}]),
    ('OP_MOD', 10, 0, []),
    ('OP_NOP', 254, 0, []),
    ('OP_NOT', 3, 0, []),
    ('OP_OBJ_FIELD', 18, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_string, 'type': o_mem}]),
    ('OP_OBJ_LOAD', 16, CF_USE1, [
     {'addr': read_qw, 'dtyp': dt_string, 'type': o_mem}]),
    ('OP_OBJ_VALUE', 17, 0, []),
    ('OP_OF', 26, 0, []),
    ('OP_OFFSET', 25, 0, []),
    ('OP_OR', 2, 0, []),
    ('OP_POP', 14, 0, []),
    ('OP_POP_M', 33, CF_USE1, [
     {'value': read_qw, 'dtyp': dt_qword, 'type': o_imm}]),
    ('OP_PUSH', 13, CF_USE1, [
     {'value': read_qw, 'dtyp': dt_qword, 'type': o_imm}]),
    ('OP_PUSH_M', 34, CF_USE1, [
     {'value': read_qw, 'dtyp': dt_qword, 'type': o_imm}]),
    ('OP_PUSH_RULE', 27, CF_USE1, [{
     'addr': read_qw, 'dtyp': dt_qword, 'type': o_mem}]),
    ('OP_SHL', 8, 0, []),
    ('OP_SHR', 9, 0, []),
    ('OP_STR_EQ', 140, 0, []),
    ('OP_STR_GE', 145, 0, []),
    ('OP_STR_GT', 143, 0, []),
    ('OP_STR_LE', 144, 0, []),
    ('OP_STR_LT', 142, 0, []),
    ('OP_STR_NEQ', 141, 0, []),
    ('OP_STR_TO_BOOL', 12, 0, []),
    ('OP_SWAPUNDEF', 35, CF_USE1, [
     {'value': read_qw, 'dtyp': dt_qword, 'type': o_imm}]),
    ('OP_UINT16', 244, 0, []),
    ('OP_UINT16BE', 250, 0, []),
    ('OP_UINT32', 245, 0, []),
    ('OP_UINT32BE', 251, 0, []),
    ('OP_UINT8', 243, 0, []),
    ('OP_UINT8BE', 249, 0, []),
]


def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


class YaraProc(processor_t):
    id = 0x8000 + 0x080
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["yara"]
    plnames = ["yara"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        'header': [".rule"],
        "flag": AS_NCHRE | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0 | AS_NOTAB,
        "uflag": 0,
        "name": "y-a-r-a",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": "db",
        "a_word": "dw",
        "a_dword": "dd",
        "a_qword": "dq",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    def notify_auto_empty(self):
        """
        will open up entry point in disassembly window
        """
        ep = get_entry(get_entry_ordinal(0))
        Jump(ep)
        return 1

    @staticmethod
    def setup_reloc_references(codeseg='.text', relocseg='.reloc'):
        reloc_seg = get_segm_by_name(relocseg)
        code_seg = get_segm_by_name(codeseg)
        reloc_references = {}

        start = reloc_seg.startEA
        cur = start

        while cur < reloc_seg.endEA:
            MakeDword(cur)
            target = get_dword(cur)
            if target == YARA_RELOCATION_END_MAGIC:
                break
            cur += 4
            offset = get_dword(target)
            if offset == YARA_RELOCATION_NULL_MAGIC:
                patch_dword(target, 0)
            else:
                # true means code, otherwise data ref
                reloc_references[target] = offset, code_seg.startEA <= offset < code_seg.endEA

        return reloc_references

    def emu_operand(self, op, insn, feature, opidx):
        operand_ea = insn.ea+1+8*opidx

        if op.type == o_mem:
            dreftype = dr_R
            if op.dtyp == dt_string:
                dreftype = dr_T
                make_ascii_string(op.addr, 0, ASCSTR_C)

            add_dref(insn.ea, op.addr, dreftype)

        elif op.type == o_near:

            n = '@_{}'.format(op.addr if get_word(op.addr) != 0xfffe else 'exit')  
            MakeNameEx(op.addr, n, SN_AUTO)
            add_cref(insn.ea, op.addr, fl_JN)

    def notify_emu(self, insn):
        feature = insn.get_canon_feature()

        for i in range(3):  # max operand count
            oprnd = insn[i]
            if oprnd.type == o_void:
                break  # no more operands

            self.emu_operand(oprnd, insn, feature, i)

        if not feature & CF_STOP:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True

    def notify_out_operand(self, ctx, op):

        if op.type == o_near:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            return True

        if op.type == o_imm:
            # this way it won't make it big endian, TODO: figure out why immediates are displayed in big endin
            ctx.out_value(op, OOF_ADDR)
            return True

        if op.type == o_mem:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            return True

        return False

    def notify_out_insn(self, ctx):
        feature = ctx.insn.get_canon_feature()
        ctx.out_mnemonic()
        if feature & CF_USE1:
            ctx.out_one_operand(0)
        if feature & CF_USE2:
            ctx.out_char(',')
            ctx.out_char(' ')
            ctx.out_one_operand(1)
        if feature & CF_USE3:
            ctx.out_char(',')
            ctx.out_char(' ')
            ctx.out_one_operand(2)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return

    def notify_ana(self, insn):

        # DO ONCE, hack
        if self.relocations is None:
            # Doing this here becuase during init the segments are not yet initialized
            self.relocations = YaraProc.setup_reloc_references()

        for i in range(3):
            insn[i].type = o_void

        insn.size = 1  # at least 1 byte
        b = get_byte(insn.ea)

        assert b in self.opcode_route, '@{} {:X} not recognized as opcode'.format(
            insn.ea, b)

        insn.itype, on, ov, of, operands = self.opcode_route[b]

        if of & CF_USE1:
            insn.size += YARA_OPERAND_SIZE
        if of & CF_USE2:
            insn.size += YARA_OPERAND_SIZE
        if of & CF_USE3:
            insn.size += YARA_OPERAND_SIZE

        eaoffset = 1  # account for the first byte
        for i, opdesc in enumerate(operands):
            for k in opdesc:
                v = opdesc[k]
                if callable(opdesc[k]):
                    v, eaoffset = v(self, insn, eaoffset)
                insn[i].__setattr__(k, v)

            # relocated address to something
            operand_ea = insn.ea+1+8*i
            if operand_ea in self.relocations and insn[i].type == o_imm:
                print 'updated patch operand @', operand_ea
                insn[i].type = o_mem
                insn[i].addr = insn[i].value
                # TODO: define structs etc

        return insn.size

    def __init__(self):
        processor_t.__init__(self)
        self.reg_names = [
            # virutal
            "CS",
            "DS"
        ]

        self.reg_first_sreg = self.reg_names.index("CS")
        self.reg_code_sreg = self.reg_names.index("CS")

        self.reg_last_sreg = self.reg_names.index("DS")
        self.reg_data_sreg = self.reg_names.index("DS")

        # required for IDA
        self.instruc = [
            {"name": on, "feature": of} for on, ov, of, operands in opcodes
        ]

        self.instruc_end = len(self.instruc)

        # for my convenience
        self.opcode_route = {}
        for i, (on, ov, of, operands) in enumerate(opcodes):
            self.opcode_route[ov] = (i, on, ov, of, operands)

        self.relocations = None  # will be initalized later


def PROCESSOR_ENTRY():
    return YaraProc()
