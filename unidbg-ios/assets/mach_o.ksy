# http://www.stonedcoder.org/~kd/lib/MachORuntime.pdf
# https://opensource.apple.com/source/python_modules/python_modules-43/Modules/macholib-1.5.1/macholib-1.5.1.tar.gz
# https://github.com/comex/cs/blob/master/macho_cs.py
# https://opensource.apple.com/source/Security/Security-55471/libsecurity_codesigning/requirements.grammar.auto.html
# https://github.com/opensource-apple/xnu/blob/10.11/bsd/sys/codesign.h
meta:
  id: mach_o
  endian: le
seq:
  - id: magic
    type: u4be
    enum: magic_type
  - id: fat_header
    type: fat_header
    if: magic == magic_type::fat_be or magic == magic_type::fat_le
  - id: header
    type: mach_header
    if: magic != magic_type::fat_be and magic != magic_type::fat_le
  - id: load_commands
    type: load_command
    if: magic != magic_type::fat_be and magic != magic_type::fat_le
    repeat: expr
    repeat-expr: header.ncmds
enums:
  magic_type:
    0xFEEDFACE: macho_be_x86 # MH_MAGIC:    mach-o, big-endian,    x86
    0xCEFAEDFE: macho_le_x86 # MH_CIGAM:    mach-o, little-endian, x86
    0xFEEDFACF: macho_be_x64 # MH_MAGIC_64: mach-o, big-endian,    x64
    0xCFFAEDFE: macho_le_x64 # MH_CIGAM_64: mach-o, little-endian, x64
    0xCAFEBABE: fat_be       # FAT_MAGIC:   fat,    big-endian
    0xBEBAFECA: fat_le       # FAT_CIGAM:   fat,    little-endian
  cpu_type:
    0xffffffff: any
    1:          vax
    2:          romp
    4:          ns32032
    5:          ns32332
    7:          i386
    8:          mips
    9:          ns32532
    11:         hppa
    12:         arm
    13:         mc88000
    14:         sparc
    15:         i860
    16:         i860_little
    17:         rs6000
    18:         powerpc
    0x1000000:  abi64     # flag
    0x1000007:  x86_64    # abi64 | i386
    0x1000012:  powerpc64 # abi64 | powerpc
    0x100000c:  arm64     # abi64 | arm
  file_type:
    # http://opensource.apple.com//source/xnu/xnu-1456.1.26/EXTERNAL_HEADERS/mach-o/loader.h
    0x1: object      # relocatable object file
    0x2: execute     # demand paged executable file
    0x3: fvmlib      # fixed VM shared library file
    0x4: core        # core file
    0x5: preload     # preloaded executable file
    0x6: dylib       # dynamically bound shared library
    0x7: dylinker    # dynamic link editor
    0x8: bundle      # dynamically bound bundle file
    0x9: dylib_stub  # shared library stub for static linking only, no section contents
    0xa: dsym        # companion file with only debug sections
    0xb: kext_bundle # x86_64 kexts    
  load_command_type:
    # http://opensource.apple.com//source/xnu/xnu-1456.1.26/EXTERNAL_HEADERS/mach-o/loader.h
    0x80000000: req_dyld
    0x1       : segment        # segment of this file to be mapped
    0x2       : symtab         # link-edit stab symbol table info
    0x3       : symseg         # link-edit gdb symbol table info (obsolete)
    0x4       : thread         # thread
    0x5       : unix_thread    # unix thread (includes a stack)
    0x6       : load_fvm_lib   # load a specified fixed VM shared library
    0x7       : id_fvm_lib     # fixed VM shared library identification
    0x8       : ident          # object identification info (obsolete)
    0x9       : fvm_file       # fixed VM file inclusion (internal use)
    0xa       : prepage        # prepage command (internal use)
    0xb       : dysymtab       # dynamic link-edit symbol table info
    0xc       : load_dylib     # load a dynamically linked shared library
    0xd       : id_dylib       # dynamically linked shared lib ident
    0xe       : load_dylinker  # load a dynamic linker
    0xf       : id_dylinker    # dynamic linker identification
    0x10      : prebound_dylib # modules prebound for a dynamically
    # linked shared library
    0x11      : routines           # image routines
    0x12      : sub_framework      # sub framework
    0x13      : sub_umbrella       # sub umbrella
    0x14      : sub_client         # sub client
    0x15      : sub_library        # sub library
    0x16      : twolevel_hints     # two-level namespace lookup hints
    0x17      : prebind_cksum      # prebind checksum
    0x80000018: load_weak_dylib    # load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported)
    0x19      : segment_64         # 64-bit segment of this file to be mapped
    0x1a      : routines_64        # 64-bit image routines
    0x1b      : uuid               # the uuid
    0x8000001c: rpath              # runpath additions
    0x1d      : code_signature     # local of code signature
    0x1e      : segment_split_info # local of info to split segments
    0x8000001f: reexport_dylib     # load and re-export dylib
    0x20      : lazy_load_dylib    # delay load of dylib until first use
    0x21      : encryption_info    # encrypted segment information
    0x22      : dyld_info          # compressed dyld information
    0x80000022: dyld_info_only     # compressed dyld information only
    0x80000023: load_upward_dylib
    0x24      : version_min_macosx
    0x25      : version_min_iphoneos
    0x26      : function_starts
    0x27      : dyld_environment
    0x80000028: main
    0x29      : data_in_code
    0x2A      : source_version
    0x2B      : dylib_code_sign_drs
    0x2C      : encryption_info_64
    0x2D      : linker_option
    0x2E      : linker_optimization_hint
    0x2F      : version_min_tvos
    0x30      : version_min_watchos
    0x32      : build_version
types:
  macho_flags:
    params:
      - id: value
        type: u4
    instances:
      no_undefs:
        value: value & 0x1 != 0
        doc: "the object file has no undefined references"
      incr_link:
        value: value & 0x2 != 0
        doc: "the object file is the output of an incremental link against a base file and can't be link edited again"
      dyld_link:
        value: value & 0x4 != 0
        doc: "the object file is input for the dynamic linker and can't be staticly link edited again"
      bind_at_load:
        value: value & 0x8 != 0
        doc: "the object file's undefined references are bound by the dynamic linker when loaded."
      prebound:
        value: value & 0x10 != 0
        doc: "the file has its dynamic undefined references prebound."
      split_segs:
        value: value & 0x20 != 0
        doc: "the file has its read-only and read-write segments split"
      lazy_init:
        value: value & 0x40 != 0
        doc: "the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)"
      two_level:
        value: value & 0x80 != 0
        doc: "the image is using two-level name space bindings"
      force_flat:
        value: value & 0x100 != 0
        doc: "the executable is forcing all images to use flat name space bindings"
      no_multi_defs:
        value: value & 0x200 != 0
        doc: "this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used."
      no_fix_prebinding:
        value: value & 0x400 != 0
        doc: "do not have dyld notify the prebinding agent about this executable"
      prebindable:
        value: value & 0x800 != 0
        doc: "the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set."
      all_mods_bound:
        value: value & 0x1000 != 0
        doc: "indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set."
      subsections_via_symbols:
        value: value & 0x2000 != 0
        doc: "safe to divide up the sections into sub-sections via symbols for dead code stripping"
      canonical:
        value: value & 0x4000 != 0
        doc: "the binary has been canonicalized via the unprebind operation"
      weak_defines:
        value: value & 0x8000 != 0
        doc: "the final linked image contains external weak symbols"
      binds_to_weak:
        value: value & 0x10000 != 0
        doc: "the final linked image uses weak symbols"
      allow_stack_execution:
        value: value & 0x20000 != 0
        doc: "When this bit is set, all stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes."
      root_safe:
        value: value & 0x40000 != 0
        doc: "When this bit is set, the binary declares it is safe for use in processes with uid zero"
      setuid_safe:
        value: value & 0x80000 != 0
        doc: "When this bit is set, the binary declares it is safe for use in processes when issetugid() is true"
      no_reexported_dylibs:
        value: value & 0x100000 != 0
        doc: "When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported"
      pie:
        value: value & 0x200000 != 0
        doc: "When this bit is set, the OS will load the main executable at a random address. Only used in MH_EXECUTE filetypes."
      dead_strippable_dylib:
        value: value & 0x400000 != 0
      has_tlv_descriptors:
        value: value & 0x800000 != 0
      no_heap_execution:
        value: value & 0x1000000 != 0
      app_extension_safe:
        value: value & 0x2000000 != 0
    -webide-representation: "{this:flags}"
  fat_arch:
    seq:
      - id: cputype
        type: u4be
        enum: cpu_type
      - id: cpusubtype
        type: u4be
      - id: offset
        type: u4be
      - id: size
        type: u4be
      - id: align
        type: u4be
  fat_header:
    seq:
      - id: nfat_arch
        type: u4be
      - id: fat_archs
        type: fat_arch
        repeat: expr
        repeat-expr: nfat_arch
  mach_header:
    seq:
      - id: cputype
        type: u4
        enum: cpu_type
      - id: cpusubtype
        type: u4
      - id: filetype
        type: u4
        enum: file_type
      - id: ncmds
        type: u4
      - id: sizeofcmds
        type: u4
      - id: flags
        type: u4
      - id: reserved
        type: u4
        if: _root.magic == magic_type::macho_be_x64 or _root.magic == magic_type::macho_le_x64
    instances:
      flags_obj:
        type: macho_flags(flags)
        -webide-parse-mode: eager
  load_command:
    seq:
      - id: type
        type: u4
        enum: load_command_type
      - id: size
        -orig-id: cmdsize
        type: u4
      - id: body
        size: size - 8
        type:
          switch-on: type
          cases:
            'load_command_type::segment_64'              : segment_command_64
            'load_command_type::segment'                 : segment_command
            'load_command_type::dyld_info'               : dyld_info_command
            'load_command_type::dyld_info_only'          : dyld_info_command
            'load_command_type::symtab'                  : symtab_command
            'load_command_type::dysymtab'                : dysymtab_command
            'load_command_type::load_dylinker'           : dylinker_command
            'load_command_type::id_dylinker'             : dylinker_command
            'load_command_type::dyld_environment'        : dylinker_command
            'load_command_type::uuid'                    : uuid_command
            'load_command_type::version_min_macosx'      : version_min_command
            'load_command_type::version_min_iphoneos'    : version_min_command
            'load_command_type::version_min_tvos'        : version_min_command
            'load_command_type::version_min_watchos'     : version_min_command
            'load_command_type::build_version'           : build_version_command
            'load_command_type::source_version'          : source_version_command
            'load_command_type::main'                    : entry_point_command
            'load_command_type::load_dylib'              : dylib_command
            'load_command_type::load_upward_dylib'       : dylib_command
            'load_command_type::id_dylib'                : dylib_command
            'load_command_type::load_weak_dylib'         : dylib_command
            'load_command_type::lazy_load_dylib'         : dylib_command
            'load_command_type::reexport_dylib'          : dylib_command
            'load_command_type::rpath'                   : rpath_command
            'load_command_type::function_starts'         : linkedit_data_command
            'load_command_type::data_in_code'            : linkedit_data_command
            'load_command_type::dylib_code_sign_drs'     : linkedit_data_command
            'load_command_type::linker_optimization_hint': linkedit_data_command
            'load_command_type::segment_split_info'      : linkedit_data_command
            'load_command_type::code_signature'          : code_signature_command
            'load_command_type::encryption_info_64'      : encryption_info_command
            'load_command_type::encryption_info'         : encryption_info_command
            'load_command_type::twolevel_hints'          : twolevel_hints_command
            'load_command_type::linker_option'           : linker_option_command
            'load_command_type::sub_framework'           : sub_command
            'load_command_type::sub_umbrella'            : sub_command
            'load_command_type::sub_client'              : sub_command
            'load_command_type::sub_library'             : sub_command
            'load_command_type::routines_64'             : routines_command_64
            'load_command_type::routines'                : routines_command
    -webide-representation: '{type}: {body}'
  vm_prot:
    seq:
      - id: strip_read
        type: b1
        doc: Special marker to support execute-only protection.
        -orig-id: VM_PROT_STRIP_READ
      - id: is_mask
        doc: Indicates to use value as a mask against the actual protection bits.
        -orig-id: VM_PROT_IS_MASK
        type: b1
      - id: reserved0
        type: b1
        doc: Reserved (unused) bit.
      - id: copy
        type: b1
        doc: Used when write permission can not be obtained, to mark the entry as COW.
        -orig-id: VM_PROT_COPY
      - id: no_change
        type: b1
        doc: Used only by memory_object_lock_request to indicate no change to page locks.
        -orig-id: VM_PROT_NO_CHANGE
      - id: execute
        type: b1
        doc: Execute permission.
        -orig-id: VM_PROT_EXECUTE
      - id: write
        type: b1
        doc: Write permission.
        -orig-id: VM_PROT_WRITE
      - id: read
        type: b1
        doc: Read permission.
        -orig-id: VM_PROT_READ
      - id: reserved1
        type: b24
        doc: Reserved (unused) bits.
  uleb128:
    seq:
      - id: b1
        type: u1
      - id: b2
        type: u1
        if: "b1 & 0x80 != 0"
      - id: b3
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0"
      - id: b4
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0 and b3 & 0x80 != 0"
      - id: b5
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0 and b3 & 0x80 != 0 and b4 & 0x80 != 0"
      - id: b6
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0 and b3 & 0x80 != 0 and b4 & 0x80 != 0 and b5 & 0x80 != 0"
      - id: b7
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0 and b3 & 0x80 != 0 and b4 & 0x80 != 0 and b5 & 0x80 != 0 and b6 & 0x80 != 0"
      - id: b8
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0 and b3 & 0x80 != 0 and b4 & 0x80 != 0 and b5 & 0x80 != 0 and b6 & 0x80 != 0 and b7 & 0x80 != 0"
      - id: b9
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0 and b3 & 0x80 != 0 and b4 & 0x80 != 0 and b5 & 0x80 != 0 and b6 & 0x80 != 0 and b7 & 0x80 != 0 and b8 & 0x80 != 0"
      - id: b10
        type: u1
        if: "b1 & 0x80 != 0 and b2 & 0x80 != 0 and b3 & 0x80 != 0 and b4 & 0x80 != 0 and b5 & 0x80 != 0 and b6 & 0x80 != 0 and b7 & 0x80 != 0 and b8 & 0x80 != 0 and b9 & 0x80 != 0"
    instances:
      value:
        value: >
          ((b1  % 128) <<  0) + ((b1 & 0x80 == 0) ? 0 :
          ((b2  % 128) <<  7) + ((b2 & 0x80 == 0) ? 0 :
          ((b3  % 128) << 14) + ((b3 & 0x80 == 0) ? 0 :
          ((b4  % 128) << 21) + ((b4 & 0x80 == 0) ? 0 :
          ((b5  % 128) << 28) + ((b5 & 0x80 == 0) ? 0 :
          ((b6  % 128) << 35) + ((b6 & 0x80 == 0) ? 0 :
          ((b7  % 128) << 42) + ((b7 & 0x80 == 0) ? 0 :
          ((b8  % 128) << 49) + ((b8 & 0x80 == 0) ? 0 :
          ((b9  % 128) << 56) + ((b8 & 0x80 == 0) ? 0 :
          ((b10 % 128) << 63))))))))))
        -webide-parse-mode: eager
    -webide-representation: "{value:dec}"
  segment_command:
    seq:
      - id: segname
        type: str
        size: 16
        pad-right: 0
        encoding: ascii
      - id: vmaddr
        type: u4
      - id: vmsize
        type: u4
      - id: fileoff
        type: u4
      - id: filesize
        type: u4
      - id: maxprot
        type: vm_prot
      - id: initprot
        type: vm_prot
      - id: nsects
        type: u4
      - id: flags
        type: u4
      - id: sections
        type: section
        repeat: expr
        repeat-expr: nsects
    types:
      section:
        seq:
          - id: sect_name
            -orig-id: sectname
            size: 16
            type: str
            pad-right: 0
            encoding: ascii
          - id: seg_name
            -orig-id: segname
            size: 16
            type: str
            pad-right: 0
            encoding: ascii
          - id: addr
            type: u4
          - id: size
            type: u4
          - id: offset
            type: u4
          - id: align
            type: u4
          - id: reloff
            type: u4
          - id: nreloc
            type: u4
          - id: flags
            type: u4
          - id: reserved1
            type: u4
          - id: reserved2
            type: u4
  segment_command_64:
    seq:
      - id: segname
        type: str
        size: 16
        pad-right: 0
        encoding: ascii
      - id: vmaddr
        type: u8
      - id: vmsize
        type: u8
      - id: fileoff
        type: u8
      - id: filesize
        type: u8
      - id: maxprot
        type: vm_prot
      - id: initprot
        type: vm_prot
      - id: nsects
        type: u4
      - id: flags
        type: u4
      - id: sections
        type: section_64
        repeat: expr
        repeat-expr: nsects
    types:
      section_64:
        seq:
          - id: sect_name
            -orig-id: sectname
            size: 16
            type: str
            pad-right: 0
            encoding: ascii
          - id: seg_name
            -orig-id: segname
            size: 16
            type: str
            pad-right: 0
            encoding: ascii
          - id: addr
            type: u8
          - id: size
            type: u8
          - id: offset
            type: u4
          - id: align
            type: u4
          - id: reloff
            type: u4
          - id: nreloc
            type: u4
          - id: flags
            type: u4
          - id: reserved1
            type: u4
          - id: reserved2
            type: u4
          - id: reserved3
            type: u4
        instances:
          data:
            io: _root._io
            pos: offset
            size: size
            type:
              switch-on: sect_name
              cases:
                "'__cstring'":        string_list
                "'__objc_methname'":  string_list
                "'__objc_classname'": string_list
                "'__objc_methtype'":  string_list
                "'__nl_symbol_ptr'":  pointer_list
                "'__got'":            pointer_list
                "'__la_symbol_ptr'":  pointer_list
                "'__cfstring'":       cf_string_list
                "'__objc_classlist'": pointer_list
                "'__objc_nlclslist'": pointer_list
                "'__objc_protolist'": pointer_list
                "'__objc_imageinfo'": pointer_list
                "'__objc_selrefs'":   pointer_list
                "'__objc_protorefs'": pointer_list
                "'__objc_classrefs'": pointer_list
                "'__objc_superrefs'": pointer_list
                "'__eh_frame'":       eh_frame
        types:
          # https://reviews.llvm.org/D15502#b8fe88d5
          eh_frame:
            seq:
              - id: items
                type: eh_frame_item
                repeat: eos
          eh_frame_item:
            seq:
              - id: length
                type: u4
              - id: length64
                type: u8
                if: length == 0xffffffff
              - id: id
                type: u4
              - id: body
                size: length - 4
                if: length > 0 and id == 0
                type: cie
            -webide-representation: '{body}'
            types:
              char_chain:
                seq:
                  - id: chr
                    type: u1
                  - id: next
                    type: char_chain
                    if: chr != 0
              cie:
                seq:
                  - id: version
                    type: u1
                  #- id: augmentation_string
                  #  type: strz
                  #  encoding: ascii
                  - id: aug_str
                    type: char_chain
                  #- id: eh_data
                  #  type: u8
                  #  if: "'eh' in augmentation_string"
                  - id: code_alignment_factor
                    type: uleb128
                  - id: data_alignment_factor
                    type: uleb128
                  - id: return_address_register
                    type: u1
                  - id: augmentation
                    type: augmentation_entry
                    if: 'aug_str.chr == 122'
                -webide-representation: 'v:{version:dec} aug:{augmentation_string} code:{code_alignment_factor} data:{data_alignment_factor} returnReg:{return_address_register}'
              augmentation_entry:
                seq:
                  - id: length
                    type: uleb128
                  - id: fde_pointer_encoding
                    type: u1
                    if: _parent.aug_str.next.chr == 82
          string_list:
            seq:
              - id: strings
                type: strz
                encoding: ascii
                repeat: eos
          pointer_list:
            seq:
              - id: items
                type: u8
                repeat: eos
          cf_string:
            seq:
              - id: isa
                type: u8
              - id: info
                type: u8
              - id: data
                type: u8
              - id: length
                type: u8
            -webide-representation: "isa={isa}, info={info}, data={data}, length={length}"
          cf_string_list:
            seq:
              - id: items
                type: cf_string
                repeat: eos
        -webide-representation: '{sect_name}: offs={offset}, size={size}'
    -webide-representation: '{segname} ({initprot}): offs={fileoff}, size={filesize}'
  dyld_info_command:
    seq:
      - id: rebase_off
        type: u4
      - id: rebase_size
        type: u4
      - id: bind_off
        type: u4
      - id: bind_size
        type: u4
      - id: weak_bind_off
        type: u4
      - id: weak_bind_size
        type: u4
      - id: lazy_bind_off
        type: u4
      - id: lazy_bind_size
        type: u4
      - id: export_off
        type: u4
      - id: export_size
        type: u4
    -webide-representation: 'rebase={rebase_off}, bind={bind_off}, weakBind={weak_bind_off}, lazyBind={lazy_bind_off}, export={export_off}'
    instances:
      rebase:
        io: _root._io
        pos: rebase_off
        size: rebase_size
        type: rebase_data
      bind:
        io: _root._io
        pos: bind_off
        size: bind_size
        type: bind_data
      lazy_bind:
        io: _root._io
        pos: lazy_bind_off
        size: lazy_bind_size
        type: lazy_bind_data
      exports:
        io: _root._io
        pos: export_off
        size: export_size
        type: export_node
    types:
      rebase_data:
        seq:
          - id: items
            type: rebase_item
            repeat: until
            repeat-until: _.opcode == opcode::done
        types:
          rebase_item:
            seq:
              - id: opcode_and_immediate
                type: u1
              - id: uleb
                type: uleb128
                if: >
                  opcode == opcode::set_segment_and_offset_uleb or
                  opcode == opcode::add_address_uleb or
                  opcode == opcode::do_rebase_uleb_times or
                  opcode == opcode::do_rebase_add_address_uleb or
                  opcode == opcode::do_rebase_uleb_times_skipping_uleb
              - id: skip
                type: uleb128
                if: "opcode == opcode::do_rebase_uleb_times_skipping_uleb"
            instances:
              opcode:
                value: "opcode_and_immediate & 0xf0"
                enum: opcode
                -webide-parse-mode: eager
              immediate:
                value: "opcode_and_immediate & 0x0f"
                -webide-parse-mode: eager
            -webide-representation: "{opcode}, imm:{immediate}, uleb:{uleb}, skip:{skip}"
        enums:
          opcode:
            0x00: done
            0x10: set_type_immediate
            0x20: set_segment_and_offset_uleb
            0x30: add_address_uleb
            0x40: add_address_immediate_scaled
            0x50: do_rebase_immediate_times
            0x60: do_rebase_uleb_times
            0x70: do_rebase_add_address_uleb
            0x80: do_rebase_uleb_times_skipping_uleb
      bind_item:
        seq:
          - id: opcode_and_immediate
            type: u1
          - id: uleb
            type: uleb128
            if: >
              opcode == bind_opcode::set_dylib_ordinal_uleb or
              opcode == bind_opcode::set_append_sleb or
              opcode == bind_opcode::set_segment_and_offset_uleb or
              opcode == bind_opcode::add_address_uleb or
              opcode == bind_opcode::do_bind_add_address_uleb or
              opcode == bind_opcode::do_bind_uleb_times_skipping_uleb
          - id: skip
            type: uleb128
            if: "opcode == bind_opcode::do_bind_uleb_times_skipping_uleb"
          - id: symbol
            type: strz
            if: "opcode == bind_opcode::set_symbol_trailing_flags_immediate"
            encoding: ascii
        instances:
          opcode:
            value: "opcode_and_immediate & 0xf0"
            enum: bind_opcode
            -webide-parse-mode: eager
          immediate:
            value: "opcode_and_immediate & 0x0f"
            -webide-parse-mode: eager
        -webide-representation: "{opcode}, imm:{immediate}, uleb:{uleb}, skip:{skip}, symbol:{symbol}"
      bind_data:
        seq:
          - id: items
            type: bind_item
            repeat: until
            repeat-until: _.opcode == bind_opcode::done
      lazy_bind_data:
        seq:
          - id: items
            type: bind_item
            repeat: eos
      export_node:
        seq:
          - id: terminal_size
            type: uleb128
          - id: children_count
            type: u1
          - id: children
            type: child
            repeat: expr
            repeat-expr: children_count
          - id: terminal
            size: terminal_size.value
        -webide-representation: "{children_count} children, term_size={terminal_size.value}"
        types:
          child:
            seq:
              - id: name
                type: strz
                encoding: ascii
              - id: node_offset
                type: uleb128
            instances:
              value:
                pos: node_offset.value
                type: export_node
            -webide-representation: "{name}: {node_offset}"
    enums:
      bind_opcode:
        0x00: done
        0x10: set_dylib_ordinal_immediate
        0x20: set_dylib_ordinal_uleb
        0x30: set_dylib_special_immediate
        0x40: set_symbol_trailing_flags_immediate
        0x50: set_type_immediate
        0x60: set_append_sleb
        0x70: set_segment_and_offset_uleb
        0x80: add_address_uleb
        0x90: do_bind
        0xa0: do_bind_add_address_uleb
        0xb0: do_bind_add_address_immediate_scaled
        0xc0: do_bind_uleb_times_skipping_uleb
  symtab_command:
    seq:
      - id: sym_off
        -orig-id: symoff
        type: u4
      - id: n_syms
        -orig-id: nsyms
        type: u4
      - id: str_off
        -orig-id: stroff
        type: u4
      - id: str_size
        -orig-id: strsize
        type: u4
    instances:
      symbols:
        io: _root._io
        pos: sym_off
        type: nlist
        repeat: expr
        repeat-expr: n_syms
      strs:
        io: _root._io
        pos: str_off
        type: str_table
        size: str_size
    -webide-representation: "symbols: {n_syms:dec}, strtab: {str_off}"
    types:
      str_table:
        seq:
          - id: unknown
            type: u4
          - id: items
            type: strz
            encoding: ascii
            repeat: until
            repeat-until: _ == ""
      nlist:
        seq:
          - id: un
            type: u4
          - id: type
            type: u1
          - id: sect
            type: u1
          - id: desc
            type: u2
          - id: value
            type:
              switch-on: _root.magic
              cases:
                'magic_type::macho_be_x64': u8
                'magic_type::macho_le_x64': u8
                'magic_type::macho_be_x86': u4
                'magic_type::macho_le_x86': u4
        -webide-representation: "un={un} type={type} sect={sect} desc={desc} value={value}"
  dysymtab_command:
    seq:
      - id: i_local_sym
        -orig-id: ilocalsym
        type: u4
      - id: n_local_sym
        -orig-id: nlocalsym
        type: u4
      - id: i_ext_def_sym
        -orig-id: iextdefsym
        type: u4
      - id: n_ext_def_sym
        -orig-id: nextdefsym
        type: u4
      - id: i_undef_sym
        -orig-id: iundefsym
        type: u4
      - id: n_undef_sym
        -orig-id: nundefsym
        type: u4
      - id: toc_off
        -orig-id: tocoff
        type: u4
      - id: n_toc
        -orig-id: ntoc
        type: u4
      - id: mod_tab_off
        -orig-id: modtaboff
        type: u4
      - id: n_mod_tab
        -orig-id: nmodtab
        type: u4
      - id: ext_ref_sym_off
        -orig-id: extrefsymoff
        type: u4
      - id: n_ext_ref_syms
        -orig-id: nextrefsyms
        type: u4
      - id: indirect_sym_off
        -orig-id: indirectsymoff
        type: u4
      - id: n_indirect_syms
        -orig-id: nindirectsyms
        type: u4
      - id: ext_rel_off
        -orig-id: extreloff
        type: u4
      - id: n_ext_rel
        -orig-id: nextrel
        type: u4
      - id: loc_rel_off
        -orig-id: locreloff
        type: u4
      - id: n_loc_rel
        -orig-id: nlocrel
        type: u4
    instances:
      indirect_symbols:
        io: _root._io
        pos: indirect_sym_off
        type: u4
        repeat: expr
        repeat-expr: n_indirect_syms
  lc_str:
    seq:
      - id: length
        -orig-id: offset
        type: u4
      - id: value
        -orig-id: ptr
        type: strz
        encoding: UTF-8
    -webide-representation: '{value}'
  dylinker_command:
    seq:
      - id: name
        type: lc_str
    -webide-representation: '{name}'
  uuid_command:
    seq:
      - id: uuid
        size: 16
    -webide-representation: 'uuid={uuid}'
  version:
    seq:
      - id: p1
        type: u1
      - id: minor
        type: u1
      - id: major
        type: u1
      - id: release
        type: u1
    -webide-representation: '{major:dec}.{minor:dec}'
  encryption_info_command:
    seq:
      - id: cryptoff
        type: u4
      - id: cryptsize
        type: u4
      - id: cryptid
        type: u4
      - id: pad
        type: u4
        if: _root.magic == magic_type::macho_be_x64 or _root.magic == magic_type::macho_le_x64
  twolevel_hints_command:
    seq:
      - id: offset
        type: u4
      - id: num_hints
        -orig-id: nhints
        type: u4
  linker_option_command:
    seq:
      - id: num_strings
        -orig-id: count
        type: u4
      - id: strings
        type: strz
        encoding: utf-8
        repeat: expr
        repeat-expr: num_strings
  sub_command:
    seq:
      - id: name
        type: lc_str
  routines_command_64:
    seq:
        - id: init_address
          type: u8
        - id: init_module
          type: u8
        - id: reserved
          size: 48 # u8 * 6
  routines_command:
    seq:
        - id: init_address
          type: u4
        - id: init_module
          type: u4
        - id: reserved
          size: 24 # u4 * 6
  version_min_command:
    seq:
      - id: version
        type: version
      - id: sdk
        type: version
    -webide-representation: 'v:{version}, r:{reserved}'
  build_tool_version:
    seq:
      - id: tool
        type: u4
        enum: build_tool
      - id: version
        type: version
    enums:
      build_tool:
        1: clang
        2: swift
        3: ld
  build_version_command:
    seq:
      - id: platform
        type: u4
        enum: build_platform
      - id: minos
        type: version
      - id: sdk
        type: version
      - id: ntools
        type: u4
      - id: build_tool_versions
        type: build_tool_version
        repeat: expr
        repeat-expr: ntools
    enums:
      build_platform:
        1: macos
        2: ios
        3: tvos
        4: watchos
        5: bridgeos
  source_version_command:
    seq:
      - id: version
        type: u8
    -webide-representation: 'v:{version:dec}'
  entry_point_command:
    seq:
      - id: entry_off
        -orig-id: entryoff
        type: u8
      - id: stack_size
        -orig-id: stacksize
        type: u8
    -webide-representation: 'entry_off={entry_off}, stack_size={stack_size}'
  dylib_command:
    seq:
      - id: name_offset
        type: u4
      - id: timestamp
        type: u4
      - id: current_version
        type: u4
      - id: compatibility_version
        type: u4
      - id: name
        type: strz
        encoding: utf-8
    -webide-representation: '{name}'
  rpath_command:
    seq:
      - id: path_offset
        type: u4
      - id: path
        type: strz
        encoding: utf-8
    -webide-representation: '{path}'
  linkedit_data_command:
    seq:
      - id: data_off
        -orig-id: dataoff
        type: u4
      - id: data_size
        -orig-id: datasize
        type: u4
    -webide-representation: 'offs={data_off}, size={data_size}'
  code_signature_command:
    seq:
      - id: data_off
        type: u4
      - id: data_size
        type: u4
    instances:
      code_signature:
        io: _root._io
        pos: data_off
        type: cs_blob
        size: data_size
    -webide-representation: 'offs={data_off}, size={data_size}'        
  cs_blob:
    seq:
      - id: magic
        type: u4be
        enum: cs_magic
      - id: length
        type: u4be
      - id: body
        size: length - 8
        type:
          switch-on: magic
          cases:
            'cs_magic::requirement'       : requirement
            'cs_magic::requirements'      : requirements
            'cs_magic::code_directory'    : code_directory
            'cs_magic::entitlement'       : entitlement
            'cs_magic::blob_wrapper'      : blob_wrapper
            'cs_magic::embedded_signature': super_blob
            'cs_magic::detached_signature': super_blob
    enums:
      cs_magic:
        0xfade0c00: requirement        # CSMAGIC_REQUIREMENT
        0xfade0c01: requirements       # CSMAGIC_REQUIREMENTS
        0xfade0c02: code_directory     # CSMAGIC_CODEDIRECTORY
        0xfade7171: entitlement        # CSMAGIC_ENTITLEMENT
        0xfade0b01: blob_wrapper       # CSMAGIC_BLOBWRAPPER
        0xfade0cc0: embedded_signature # CSMAGIC_EMBEDDED_SIGNATURE
        0xfade0cc1: detached_signature # CSMAGIC_DETACHED_SIGNATURE
    types:
      code_directory:
        seq:
          - id: version
            type: u4be
          - id: flags
            type: u4be
          - id: hash_offset
            type: u4be
          - id: ident_offset
            type: u4be
          - id: n_special_slots
            type: u4be
          - id: n_code_slots
            type: u4be
          - id: code_limit
            type: u4be
          - id: hash_size
            type: u1
          - id: hash_type
            type: u1
          - id: spare1
            type: u1
          - id: page_size
            type: u1
          - id: spare2
            type: u4be
          - id: scatter_offset
            type: u4be
            if: version >= 0x20100
          - id: team_id_offset
            type: u4be
            if: version >= 0x20200
        instances:
          ident:
            pos: ident_offset - 8
            type: strz
            encoding: utf-8
            -webide-parse-mode: eager
          team_id:
            pos: team_id_offset - 8
            type: strz
            encoding: utf-8
            -webide-parse-mode: eager
          hashes:
            pos: hash_offset - 8 - hash_size * n_special_slots
            repeat: expr
            repeat-expr: n_special_slots + n_code_slots
            size: hash_size
      blob_index:
        seq:
          - id: type
            type: u4be
            enum: csslot_type
          - id: offset
            type: u4be
        instances:
          blob:
            pos: offset - 8
            io: _parent._io
            size-eos: true
            type: cs_blob
        enums:
          csslot_type:
            0:       code_directory             # CSSLOT_CODEDIRECTORY
            1:       info_slot                  # CSSLOT_INFOSLOT
            2:       requirements               # CSSLOT_REQUIREMENTS
            3:       resource_dir               # CSSLOT_RESOURCEDIR
            4:       application                # CSSLOT_APPLICATION
            5:       entitlements               # CSSLOT_ENTITLEMENTS
            0x1000:  alternate_code_directories # CSSLOT_ALTERNATE_CODEDIRECTORIES
            0x10000: signature_slot             # CSSLOT_SIGNATURESLOT
      data:
        seq:
          - id: length
            type: u4be
          - id: value
            size: length
          - id: padding
            size: 4 - (length & 3)
        -webide-representation: "{value}"
      match:
        seq:
          - id: match_op
            type: u4be
            enum: op
          - id: data
            type: data
            if: 'match_op != op::exists'
        enums:
          op:
            0: exists
            1: equal
            2: contains
            3: begins_with
            4: ends_with
            5: less_than
            6: greater_than
            7: less_equal
            8: greater_equal
        -webide-representation: "{match_op} {data.value:str}"
      expr:
        seq:
          - id: op
            type: u4be
            enum: op_enum
          - id: data
            type:
              switch-on: op
              cases:
                #'op_enum::false'               : 'false'
                #'op_enum::true'                : 'true'
                'op_enum::ident'               : ident_expr
                #'op_enum::apple_anchor'        : 'anchor apple'
                'op_enum::anchor_hash'         : anchor_hash_expr
                'op_enum::info_key_value'      : data
                'op_enum::and_op'              : and_expr
                'op_enum::or_op'               : or_expr
                'op_enum::cd_hash'             : data
                'op_enum::not_op'              : expr
                'op_enum::info_key_field'      : info_key_field_expr
                'op_enum::cert_field'          : cert_field_expr
                'op_enum::trusted_cert'        : cert_slot_expr
                #'op_enum::trusted_certs'       : 'anchor trusted'
                'op_enum::cert_generic'        : cert_generic_expr
                'op_enum::apple_generic_anchor': apple_generic_anchor_expr
                'op_enum::entitlement_field'   : entitlement_field_expr
        enums:
          op_enum:
            0: 'false'               # unconditionally false
            1: 'true'                # unconditionally true
            2: ident                 # match canonical code [string]
            3: apple_anchor          # signed by Apple as Apple's product ("anchor apple")
            4: anchor_hash           # match anchor [cert hash]
            5: info_key_value        # *legacy* - use opInfoKeyField [key; value]
            6: and_op                # binary prefix expr AND expr [expr; expr]
            7: or_op                 # binary prefix expr OR expr
            8: cd_hash               # match hash of CodeDirectory directly
            9: not_op                # logical inverse
            10: info_key_field       # Info.plist key field [string; match suffix]
            11: cert_field           # Certificate field [cert index; field name; match suffix]
            12: trusted_cert         # require trust settings to approve one particular cert [cert index]
            13: trusted_certs        # require trust settings to approve the cert chain
            14: cert_generic         # Certificate component by OID [cert index; oid; match suffix]
            15: apple_generic_anchor # signed by Apple in any capacity ("anchor apple generic")
            16: entitlement_field    # entitlement dictionary field [string; match suffix]
          cert_slot:
            0xffffffff: anchor_cert
            0: left_cert
        types:
          ident_expr:
            seq:
              - id: identifier
                type: data
            -webide-representation: "identifier {identifier.value:str}"
          apple_generic_anchor_expr:
            instances:
              value:
                value: '"anchor apple generic"'
            -webide-representation: "anchor apple generic"
          cert_slot_expr:
            seq:
              - id: value
                type: u4be
                enum: cert_slot
          and_expr:
            seq:
              - id: left
                type: expr
              - id: right
                type: expr
            -webide-representation: "({left}) AND ({right})"
          or_expr:
            seq:
              - id: left
                type: expr
              - id: right
                type: expr
            -webide-representation: "({left}) OR ({right})"
          anchor_hash_expr:
            seq:
              - id: cert_slot
                type: u4be
                enum: cert_slot
              - id: data
                type: data
          info_key_field_expr:
            seq:
              - id: data
                type: data
              - id: match
                type: match
          entitlement_field_expr:
            seq:
              - id: data
                type: data
              - id: match
                type: match
          cert_field_expr:
            seq:
              - id: cert_slot
                type: u4be
                enum: cert_slot
              - id: data
                type: data
              - id: match
                type: match
            -webide-representation: "{cert_slot}[{data.value:str}] {match}"
          cert_generic_expr:
            seq:
              - id: cert_slot
                type: u4be
                enum: cert_slot
              - id: data
                type: data
              - id: match
                type: match
            -webide-representation: "{cert_slot}[{data.value:hex}] {match}"
        -webide-representation: '{data}'
      requirement:
        seq:
          - id: kind
            type: u4be
          - id: expr
            type: expr
      entitlement:
        seq:
          - id: data
            size-eos: true
        -webide-representation: "{data:str}"
      requirements_blob_index:
        seq:
          - id: type
            type: u4be
            enum: requirement_type
          - id: offset
            type: u4be
        instances:
          value:
            type: cs_blob
            pos: offset - 8
        enums:
          requirement_type:
            1: host        # kSecHostRequirementType
            2: guest       # kSecGuestRequirementType
            3: designated  # kSecDesignatedRequirementtype
            4: library     # kSecLibraryRequirementType
      requirements:
        seq:
          - id: count
            type: u4be
          - id: items
            type: requirements_blob_index
            repeat: expr
            repeat-expr: count
      blob_wrapper:
        seq:
          - id: data
            size-eos: true
      super_blob:
        seq:
          - id: count
            type: u4be
          - id: blobs
            type: blob_index
            repeat: expr
            repeat-expr: count
