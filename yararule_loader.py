import os
from struct import unpack
from collections import namedtuple
import idaapi
import idautils
from idc import *


YARA_ARENA_TO_VERSION = {
    19: '3.8.1'
}

RULE_GFLAGS_NULL = 0x1000


class structs(object):
    YARA_RULES_FILE_HEADER = None
    YR_RULE = None


def parse_file_hdr(f):
    """
    typedef struct
    {
        QWORD rules_list_head;
        QWORD externals_list_head;
        QWORD code_start;
        QWORD ac_match_table;
        QWORD ac_transition_table;

        DWORD ac_tables_size;
        DWORD padding;

    } YARA_RULES_FILE_HEADER;
    """
    FILE_HDR = namedtuple(
        'filehdr', 'rules_list_head externals_list_head code_start ac_match_table ac_transition_table ac_tables_size')
    return FILE_HDR(*unpack('<6Q', f.read(6*8)))


def parse_hdr(f):
    """
    typedef struct {
        char magic[4];
        DWORD size;
        struct {
            WORD max_threads;
            WORD arena_ver;
        }version;
    }YR_HDR;
    """
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
    print 'sid', sid, 'ea', ea, 'strcsuze', GetStrucSize(
        sid), 'nm', get_struc_name(sid)
    return MakeStructEx(ea, GetStrucSize(sid), get_struc_name(sid))


def create_structs(hdr, file_hdr):
    # define the rule file header
    # FF_0OFF works for named references
    structs.YARA_RULES_FILE_HEADER = create_struct('YARA_RULES_FILE_HEADER', [
        ('rules_list_head', 0, FF_0OFF | FF_DWORD | FF_DATA, -1, 4),
        ('padding1', -1, FF_ALIGN, -1, 4),
        ('externals_list_head', -1, FF_DWORD | FF_DATA, -1, 4),
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


def parse_data_seg(hdr, file_hdr, f):
    create_structs(hdr, file_hdr)
    f.seek(0)

    # define ac_transition_table
    MakeDword(file_hdr.ac_transition_table)
    MakeArray(file_hdr.ac_transition_table, file_hdr.ac_tables_size)
    MakeName(file_hdr.ac_transition_table, 'ac_transition_table')

    # define ac_match_table
    MakeDword(file_hdr.ac_match_table)
    MakeArray(file_hdr.ac_match_table, file_hdr.ac_tables_size)
    MakeName(file_hdr.ac_match_table, 'ac_match_table')

    print 'set struct hdr:', set_ea_to_struc(0, structs.YARA_RULES_FILE_HEADER)

    rule_size = GetStrucSize(structs.YR_RULE)
    f.seek(file_hdr.rules_list_head+0x0c)
    rule_count = 1
    while True:
        gflags = unpack('<I', f.read(4))[0]
        print 'rule %d gflags: %X' % (rule_count, gflags)
        if gflags & RULE_GFLAGS_NULL:
            break
        set_ea_to_struc(f.tell()-4-0x0c, structs.YR_RULE)
        MakeName(f.tell()-4 - 0x0c, 'rule_%d' % rule_count)
        f.seek(rule_size - 4, os.SEEK_CUR)
        rule_count += 1

    set_ea_to_struc(f.tell()-4-0x0c, structs.YR_RULE)
    MakeName(f.tell()-4-0x0c, 'null_rule')


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
    # note specifying CODE since it will force decoding of data that's in the section for padding (TODO: setup padding somehow)
    idaapi.add_segm(0, file_hdr.code_start, code_end, ".text", "")
    # this will allow string references to work later
    idaapi.add_segm(0, 0, file_hdr.code_start, ".data", "DATA")
    idaapi.add_segm(0, code_end, mapsize, ".data", "DATA")
    idaapi.add_segm(0, mapsize, flen-0x0c, ".reloc", "RELOC")

    parse_data_seg(hdr, file_hdr, f)

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
