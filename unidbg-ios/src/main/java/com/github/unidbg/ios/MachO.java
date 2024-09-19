package com.github.unidbg.ios;

@SuppressWarnings("unused")
public interface MachO {

    long CPU_SUBTYPE_ARM_V7 = 9;

    int MH_PIE = 0x200000;

    int SECTION_TYPE = 0x000000ff;
    int S_ZEROFILL = 0x1;
    int S_NON_LAZY_SYMBOL_POINTERS = 0x6;
    int S_LAZY_SYMBOL_POINTERS = 0x7;
    int S_MOD_INIT_FUNC_POINTERS = 0x9;
    int S_INIT_FUNC_OFFSETS = 0x16;

    long INDIRECT_SYMBOL_ABS = 0x40000000L;
    long INDIRECT_SYMBOL_LOCAL = 0x80000000L;

    int NO_SECT = 0;
    int N_TYPE = 0x0e;
    int N_STAB = 0xe0;
    int N_UNDF = 0; /* undefined, n_sect == NO_SECT */
    int N_EXT = 0x1; /* external symbol bit, set for external symbols */
    int N_ABS = 0x2; /* absolute, n_sect == NO_SECT */
    int N_SECT = 0xe; /* defined in section number n_sect */
    int N_INDR = 0xa; /* indirect */
    int N_PBUD = 0xc; /* prebound undefined (defined in a dylib) */

    int N_ARM_THUMB_DEF = 0x8; /* symbol is a Thumb function (ARM) */
    int N_WEAK_REF = 0x0040; /* symbol is weak referenced */
    int N_WEAK_DEF = 0x0080; /* coalesed symbol is a weak definition */

    int ARM_RELOC_VANILLA = 0; /* generic relocation as discribed above */

    int EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03;
    int EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00;
    int EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02;

    int EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08;
    int EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10;

    int REBASE_TYPE_POINTER = 1;
    int REBASE_TYPE_TEXT_ABSOLUTE32 = 2;

    int REBASE_IMMEDIATE_MASK = 0x0f;
    int REBASE_OPCODE_MASK = 0xf0;
    int REBASE_OPCODE_DONE = 0x00;
    int REBASE_OPCODE_SET_TYPE_IMM = 0x10;
    int REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20;
    int REBASE_OPCODE_ADD_ADDR_ULEB = 0x30;
    int REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40;
    int REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50;
    int REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60;
    int REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70;
    int REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80;

    int BIND_IMMEDIATE_MASK = 0x0f;
    byte BIND_OPCODE_MASK = (byte) 0xf0;
    int BIND_OPCODE_DONE = 0x00;
    int BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10;
    int BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20;
    int BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30;
    int BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40;
    int BIND_OPCODE_SET_TYPE_IMM = 0x50;
    int BIND_OPCODE_SET_ADDEND_SLEB = 0x60;
    int BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70;
    int BIND_OPCODE_ADD_ADDR_ULEB = 0x80;
    int BIND_OPCODE_DO_BIND = 0x90;
    int BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xa0;
    int BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0;
    int BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0;

    int BIND_TYPE_POINTER = 1;
    int BIND_TYPE_TEXT_ABSOLUTE32 = 2;
    int BIND_TYPE_TEXT_PCREL32 = 3;

    int _IONBF = 2; /* setvbuf should set unbuffered */

    int MAP_FILE = 0x0000; /* map from file (default) */
    int MAP_SHARED = 0x0001; /* [MF|SHM] share changes */
    int MAP_PRIVATE = 0x0002; /* [MF|SHM] changes are private */
    int MAP_FIXED = 0x0010; /* [MF|SHM] interpret addr exactly */
    int MAP_ANONYMOUS = 0x1000; /* allocated from memory, swap space */
    int MAP_MY_FIXED = 0x1234abcd;

    int VM_MEMORY_REALLOC = 6;

    long _COMM_PAGE32_BASE_ADDRESS = (0xffff4000L);

    long _KERNEL_BASE64 = 0xffffff80001f0000L;
    long _COMM_PAGE64_BASE_ADDRESS = _KERNEL_BASE64 + 0xc000 /* In TTBR0 */;

    int VM_FLAGS_FIXED = 0x0000;
    int VM_FLAGS_ANYWHERE = 0x0001;
    int VM_FLAGS_OVERWRITE = 0x4000; /* delete any existing mappings first */

    int F_GETPATH = 50; /* return the full path of the fd */

    byte BIND_SPECIAL_DYLIB_SELF = 0;
    byte BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1;
    byte BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2;
    byte BIND_SPECIAL_DYLIB_WEAK_LOOKUP = -3;

    int MH_WEAK_DEFINES = 0x8000; /* the final linked image contains external weak symbols */

}
