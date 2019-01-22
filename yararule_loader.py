import os
from struct import unpack
from collections import namedtuple
import idaapi
import idautils
from idc import *

YARA_ARENA_TO_VERSION = {
    16: '3.7.X',
    19: '3.8.X'
}

RULE_GFLAGS_NULL = 0x1000
UNDEFINED_MAGIC = 0xFFFABADAFABADAFF

# external types
EXTERNAL_VARIABLE_TYPE_NULL = 0
EXTERNAL_VARIABLE_TYPE_FLOAT = 1
EXTERNAL_VARIABLE_TYPE_INTEGER = 2
EXTERNAL_VARIABLE_TYPE_BOOLEAN = 3
EXTERNAL_VARIABLE_TYPE_STRING = 4
EXTERNAL_VARIABLE_TYPE_MALLOC_STRING = 5


class structs(object):
    YARA_RULES_FILE_HEADER = None
    YR_RULE = None


def parse_file_hdr(f):
    FILE_HDR = namedtuple(
        'filehdr', 'rules_list_head externals_list_head code_start ac_match_table ac_transition_table ac_tables_size')
    return FILE_HDR(*unpack('<6Q', f.read(6*8)))


def parse_hdr(f):
    HDR = namedtuple('hdr', 'magic size max_threads arena_ver')

    return HDR(f.read(4), *unpack('<I H H', f.read(0x8)))


def find_code_end(file_hdr):
    m = filter(lambda x: x > file_hdr.code_start, list(file_hdr)[:5])
    if not m:
        return None
    return min(m)


def create_struct(strucname, members=()):
    sid = AddStrucEx(-1, strucname, 0)
    assert sid != BADADDR, 'failed adding struct {}'.format(strucname)

    print "added struct \"{0}\", id: {1}".format(strucname, sid)
    setattr(structs, strucname, sid)
    for m in members:
        AddStrucMember(sid, *m)

    return sid


def set_ea_to_struc(ea, sid):
    # print 'sid', sid, 'ea', ea, 'strcsuze', GetStrucSize(
        # sid), 'nm', get_struc_name(sid)
    return MakeStructEx(ea, GetStrucSize(sid), get_struc_name(sid))


def create_structs(hdr, file_hdr):
    # define the rule file header
    # FF_0OFF works for named references
    structs.YARA_RULES_FILE_HEADER = create_struct('YARA_RULES_FILE_HEADER', [
        ('rules_list_head', 0, FF_0OFF | FF_DWORD | FF_DATA, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
        ('externals_list_head', -1, FF_0OFF | FF_DWORD | FF_DATA, -1, 4),
        ('padding2', -1, FF_ALIGN, -1, 4),
        ('code_start', -1, FF_0OFF | FF_DWORD | FF_DATA, -1, 4),
        ('padding3', -1, FF_ALIGN, -1, 4),
        ('ac_match_table', -1, FF_0OFF | FF_DWORD | FF_DATA, -1, 4),
        ('padding4', -1, FF_ALIGN, -1, 4),
        ('ac_transition_table', -1, FF_0OFF | FF_DWORD | FF_DATA, -1, 4),
        ('padding5', -1, FF_ALIGN, -1, 4),
        ('ac_tables_size', -1, FF_DWORD | FF_DATA, -1, 4),
        ('padding6', -1, FF_ALIGN, -1, 4),
    ])

    structs.YR_RULE = create_struct('YR_RULE', [
        ('g_flags', 0, FF_DWORD | FF_DATA, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
        ('t_flags', -1, FF_DWORD | FF_DATA, -1,
         4*hdr.max_threads),  # assume even number
        ('identifier', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding3', -1, FF_ALIGN, -1, 4),
        ('tags', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding4', -1, FF_ALIGN, -1, 4),
        ('metas', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding5', -1, FF_ALIGN, -1, 4),
        ('strings', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding6', -1, FF_ALIGN, -1, 4),
        ('ns', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding7', -1, FF_ALIGN, -1, 4),
        ('time_cost', -1,  FF_QWORD | FF_DATA, -1, 8),
    ])

    structs.YR_META = create_struct('YR_META', [
        ('type', 0, FF_DWORD | FF_DATA, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
        ('integer', 8, FF_QWORD | FF_DATA, -1, 8),
        ('identifier', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding2', -1, FF_ALIGN, -1, 4),
        ('string', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding3', -1, FF_ALIGN, -1, 4),
    ])

    structs.YR_NAMESPACE = create_struct('YR_NAMESPACE', [
        ('t_flags', -1, FF_DWORD | FF_DATA, -1, 4*hdr.max_threads),  # assume even
        ('name', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
    ])

    structs.YR_MATCH = create_struct('YR_MATCH', [
        ('count', -1,  FF_DWORD | FF_DATA, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
        ('head', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding2', -1, FF_ALIGN, -1, 4),
        ('tail', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding3', -1, FF_ALIGN, -1, 4),

    ])

    structs.YR_STRING = create_struct('YR_STRING', [
        ('g_flags', -1, FF_DWORD | FF_DATA, -1, 4),
        ('length', -1,  FF_DWORD | FF_DATA, -1, 4),
        ('identifier', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
        ('string', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding2', -1, FF_ALIGN, -1, 4),
        ('chained_to', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding3', -1, FF_ALIGN, -1, 4),
        ('rule', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding4', -1, FF_ALIGN, -1, 4),
        ('chain_gap_min', -1,  FF_DWORD | FF_DATA, -1, 4),
        ('chain_gap_max', -1,  FF_DWORD | FF_DATA, -1, 4),
        ('fixed_offset', -1,  FF_QWORD | FF_DATA, -1, 8),
        ('matches', -1,  FF_STRUCT, structs.YR_MATCH,
         hdr.max_threads * GetStrucSize(structs.YR_MATCH)),
        ('unconfirmed_matches', -1,  FF_STRUCT, structs.YR_MATCH,
         hdr.max_threads * GetStrucSize(structs.YR_MATCH)),
        ('time_cost', -1,  FF_QWORD | FF_DATA, -1, 8),

    ])

    structs.YR_SIZED_STRING = create_struct('YR_SIZED_STRING', [
        ('length', -1, FF_DWORD | FF_DATA, -1, 4),
        ('flags', -1,  FF_DWORD | FF_DATA, -1, 4),
        # find way of defining a variable length member
        ('c_string', -1, FF_STRLIT, -1, 1),
    ])

    structs.YR_EXTERNAL_VARIABLE = create_struct('YR_EXTERNAL_VARIABLE', [
        ('type', -1, FF_DWORD | FF_DATA, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
        ('value', -1,  FF_DWORD | FF_DATA | FF_0OFF, -1, 4), # fix in case of other types
        ('valueHigh', -1, FF_DWORD | FF_DATA, -1, 4),
        ('identifier', -1,  FF_DWORD | FF_0OFF, -1, 4),
        ('padding3', -1, FF_ALIGN, -1, 4),
    ])


def read_cstr(f):
    b = ''
    while True:
        c = f.read(1)
        if c == '' or c == '\x00':
            break

        b += c
    return b


def parse_ns(f, hdr, file_hdr, rule_start, off):
    f.seek(off+0X0C + 4*hdr.max_threads)
    set_ea_to_struc(off, structs.YR_NAMESPACE)
    nsname_off = unpack('<I', f.read(4))[0]
    if valid_struct_ptr(nsname_off):
        idaapi.make_ascii_string(nsname_off, 0, ASCSTR_C)

    f.seek(nsname_off+0x0c)
    MakeName(off, 'ns_%s' % read_cstr(f))


def parse_tags(f, hdr, file_hdr, rule_start, off):
    f.seek(off+0X0C)
    while True:
        tag_name_off = f.tell()-0x0c
        tag = read_cstr(f)
        if not tag:
            break
        idaapi.make_ascii_string(tag_name_off, 0, ASCSTR_C)
        MakeName(tag_name_off, 'tag_%s_%x' %
                 (tag, rule_start))  # tag names can repeat
    # TODO: find a way to remove the reference from struct definition if it's NULL (idc.SetMemberType ?)


def parse_strings(f, hdr, file_hdr, rule_start, off):
    str_size = GetStrucSize(structs.YR_STRING)
    str_count = 0
    while True:
        cur = off+str_count*str_size
        f.seek(cur+0x0c)
        set_ea_to_struc(cur, structs.YR_STRING)
        str_flags = unpack('I', f.read(4))[0]
        if str_flags & 0x1000:  # STRING_GFLAGS_NULL
            MakeName(cur, 'null_string_%x' % rule_start)
            break
        str_count += 1
        strlen, idntf, _, str_val_off = unpack('4I', f.read(16))
        if str_flags & 0x400 and str_flags & 0x08:  # type string literal and ascii, respectively
            idaapi.make_ascii_string(str_val_off, 0, ASCSTR_C)
            str_val = get_name(str_val_off, 0x0004)  # GN_DEMANGLED
            if not str_val:

                MakeArray(str_val_off, strlen)
                MakeName(str_val_off, 'pattern_%s' % str_count)
                str_val = '%d' % str_count

        else:
            str_val = '%d' % str_count

        str_val = 'string_%s_%x' % (str_val, rule_start)
        MakeNameEx(cur, str_val, 0x22)  # SN_PUBLIC | SN_NOCHECK

    # TODO: make enum bitmask (https://www.hex-rays.com/products/ida/support/idadoc/500.shtml https://reverseengineering.stackexchange.com/questions/14795/how-to-add-standard-symbolic-constants-with-bitwise-operators-like-ors)


def parse_metas(f, hdr, file_hdr, rule_start, off):
    f.seek(off+0X0C)
    metas_start = f.tell()
    meta_size = GetStrucSize(structs.YR_META)
    meta_count = 0
    while True:
        curr_meta = off + meta_count*meta_size
        set_ea_to_struc(curr_meta, structs.YR_META)
        meta_type, _, meta_integer, meta_name_off, _, meta_string, _ = unpack(
            '<IIQIIII', f.read(meta_size))
        if meta_type == 0:
            MakeName(curr_meta, 'meta_null_%x' % rule_start)
            break
        idaapi.make_ascii_string(meta_name_off, 0, ASCSTR_C)
        f.seek(meta_name_off + 0x0c)
        MakeName(curr_meta, 'meta_%s_%x' % (read_cstr(f), rule_start))
        if meta_type == 2:
            idaapi.make_ascii_string(meta_string, 0, ASCSTR_C)

        meta_count += 1
        f.seek(metas_start + meta_count*meta_size)


def valid_struct_ptr(file_offset):
    """
    check if file_offset not 0 before and after relocation

    relocation patches for NULL pointers hasn't happened yet, so compare to null magic
    malicious file could not use relocations (swisscheese/extracheese) so check for NULL as wekk
    """
    return file_offset != 0xfffabada and file_offset != 0


def parse_rule(f, hdr, file_hdr):
    rule_size = GetStrucSize(structs.YR_RULE)
    rule_start = f.tell() - 0x0c

    gflags, __, tflags, idntfier_off, __, tags_off, __, metas_off, __, strings_off, __, ns_off, __, time_cost = unpack(
        '<II%ss10IQ' % (4*hdr.max_threads), f.read(rule_size))

    if gflags & RULE_GFLAGS_NULL:
        f.seek(-rule_size, os.SEEK_CUR)
        return True

    set_ea_to_struc(rule_start, structs.YR_RULE)
    if valid_struct_ptr(idntfier_off):
        f.seek(idntfier_off+0X0C)
        MakeName(rule_start, 'rule_%s' % read_cstr(f))

    if valid_struct_ptr(ns_off):
        parse_ns(f, hdr, file_hdr, rule_start, ns_off)

    if valid_struct_ptr(tags_off):
        parse_tags(f, hdr, file_hdr, rule_start, tags_off)

    if valid_struct_ptr(strings_off):
        parse_strings(f, hdr, file_hdr, rule_start, strings_off)

    if valid_struct_ptr(metas_off):
        parse_metas(f, hdr, file_hdr, rule_start, metas_off)

    f.seek(rule_start+rule_size+0x0c)


def parse_external(f, hdr, file_hdr):
    ext_start = f.tell()-0x0c

    ext_size = GetStrucSize(structs.YR_EXTERNAL_VARIABLE)
    set_ea_to_struc(ext_start, structs.YR_EXTERNAL_VARIABLE)

    xtype, __, val, val64, idntfier_off, __ = unpack(
        '<2I 2I 2I', f.read(ext_size))
    if xtype == 0:
        MakeName(ext_start, 'ext_null')
        return True
    f.seek(idntfier_off+0x0c)
    MakeName(ext_start, 'ext_%s_%x' % (read_cstr(f), ext_start))

    if xtype in [EXTERNAL_VARIABLE_TYPE_STRING, EXTERNAL_VARIABLE_TYPE_MALLOC_STRING] and valid_struct_ptr(val):
        idaapi.make_ascii_string(val, 0, ASCSTR_C)
    elif xtype:  # TODO: handle other cases
        MakeQword(ext_start + 8)

    f.seek(ext_size+ext_start+0x0c)


def parse_data_seg(hdr, file_hdr, f):
    create_structs(hdr, file_hdr)
    f.seek(0)
    table_size = file_hdr.ac_tables_size
    if table_size == 0xCCCCccccCCCCcccc:  # support older version where file_hdr.ac_tables_size was unavailable
        table_size = abs(file_hdr.ac_match_table -
                         file_hdr.ac_transition_table)/4

    MakeDword(file_hdr.ac_transition_table)
    MakeArray(file_hdr.ac_transition_table, table_size)
    MakeName(file_hdr.ac_transition_table, 'ac_transition_table')

    # define ac_match_table
    MakeDword(file_hdr.ac_match_table)
    MakeArray(file_hdr.ac_match_table, table_size)
    MakeName(file_hdr.ac_match_table, 'ac_match_table')

    print 'set struct hdr:', set_ea_to_struc(0, structs.YARA_RULES_FILE_HEADER)
    MakeName(0, 'file_header')

    if valid_struct_ptr(file_hdr.externals_list_head):
        f.seek(file_hdr.externals_list_head+0x0c)
        while True:
            isnull = parse_external(f, hdr, file_hdr)
            if isnull:
                break

    f.seek(file_hdr.rules_list_head+0x0c)
    rule_count = 1
    while True:
        isnull = parse_rule(f, hdr, file_hdr)
        if isnull:
            break
        rule_count += 1

    set_ea_to_struc(f.tell()-0x0c, structs.YR_RULE)
    MakeName(f.tell()-0x0c, 'null_rule')


# -----------------------------------------------------------------------


def accept_file(f, n):
        # we support only one format per file

    if idaapi.IDA_SDK_VERSION < 700 and n > 0:
        return 0

    f.seek(0)
    if f.read(4) != 'YARA':
        return 0

    # accept the file
    return {'format': "compiled yara-rule", 'options': 1 | 0x8000}


def define_consts():
    enum = AddEnum(-1, 'YARA_CONST', idaapi.hexflag())
    if enum == BADADDR:
        print 'Unable to create enum YARA_CONST'
        return

    if idc.AddConst(enum, 'UNDEFINED_32', UNDEFINED_MAGIC & 0xFFFFffff):
        print 'Unable to create UNDEFINED_32 value'
        return

    const_id = GetConstByName('UNDEFINED_32')
    if const_id == -1:
        print 'Unable to get id of UNDEFINED_32'
        return

    if not SetConstCmt(const_id, 'internal UNDEFINED value for YARA VM', 1):
        print 'failed setting comment for UNDEFINED_32'
        return

    return True


def load_file(f, neflags, format):

    idaapi.set_processor_type('yara', idaapi.SETPROC_ALL)

    f.seek(0x0, os.SEEK_END)
    flen = f.tell()
    f.seek(0)

    hdr = parse_hdr(f)
    file_hdr = parse_file_hdr(f)
    # mark the proc type, so IDA can invoke the correct disassembler/processor.

    mapsize = hdr.size

    # map 0..mapsize from file at offset 0xc into idb (without relocation data)
    # this makes all pointers relative offsets to this mapping's start
    f.file2base(0xc, 0, flen-0x0c, True)  # true makes it patchable
    f.seek(hdr.size+0x0c)

    code_end = find_code_end(file_hdr) or hdr.size

    # list head shoule come right after (except some CC paddings. weirdly  t4.yara compiles some extra garbage between the code and rules_list_head)
    # note specifying CODE since it will force decoding of data that's in the section for padding
    idaapi.add_segm(0, file_hdr.code_start, code_end, ".text", "")
    # this will allow string references to work later
    idaapi.add_segm(0, 0, file_hdr.code_start, ".data", "DATA")
    idaapi.add_segm(0, code_end, mapsize, ".data", "DATA")
    idaapi.add_segm(0, mapsize, flen-0x0c, ".reloc", "RELOC")

    parse_data_seg(hdr, file_hdr, f)
    define_consts()
    # set up entry point
    idaapi.add_entry(file_hdr.code_start, file_hdr.code_start,
                     "start", 1)  # 1 means make code
    # some comments
    idaapi.describe(file_hdr.code_start, True,
                    "Compiled YARA rule disassembly")
    yaraver = '(yara {})'.format(
        YARA_ARENA_TO_VERSION[hdr.arena_ver]) if hdr.arena_ver in YARA_ARENA_TO_VERSION else ''
    idaapi.describe(file_hdr.code_start, True, "Arena version {} {}".format(
        hdr.arena_ver, yaraver))  # T TODO: check changes between arena versions

    idaapi.describe(file_hdr.code_start, True,
                    "max_threads: {}".format(hdr.max_threads))

    return 1
