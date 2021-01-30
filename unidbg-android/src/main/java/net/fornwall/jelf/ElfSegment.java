package net.fornwall.jelf;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Class corresponding to the Elf32_Phdr/Elf64_Phdr struct.
 * 
 * An executable or shared object file's program header table is an array of structures, each describing a segment or
 * other information the system needs to prepare the program for execution. An object file segment contains one or more
 * sections. Program headers are meaningful only for executable and shared object files. A file specifies its own
 * program header size with the ELF header's {@link ElfFile#ph_entry_size e_phentsize} and {@link ElfFile#num_ph
 * e_phnum} members.
 * 
 * http://www.sco.com/developers/gabi/latest/ch5.pheader.html#p_type
 * http://stackoverflow.com/questions/22612735/how-can-i-find-the-dynamic-libraries-required-by-an-elf-binary-in-c
 */
@SuppressWarnings("unused")
public class ElfSegment {

	/** Type defining that the array element is unused. Other member values are undefined. */
	public static final int PT_NULL = 0;
	/** Type defining that the array element specifies a loadable segment. */
	public static final int PT_LOAD = 1;
	/** The array element specifies dynamic linking information. */
	public static final int PT_DYNAMIC = 2;
	/**
	 * The array element specifies the location and size of a null-terminated path name to invoke as an interpreter.
	 * Meaningful only for executable files (though it may occur for shared objects); it may not occur more than once in
	 * a file. If it is present, it must precede any loadable segment entry.
	 */
	public static final int PT_INTERP = 3;
	/** The array element specifies the location and size of auxiliary information. */
	public static final int PT_NOTE = 4;
	/** This segment type is reserved but has unspecified semantics. */
	public static final int PT_SHLIB = 5;
	/**
	 * The array element, if present, specifies the location and size of the program header table itself, both in the
	 * file and in the memory image of the program. This segment type may not occur more than once in a file.
	 */
	public static final int PT_PHDR = 6;
	/** The array element specifies the Thread-Local Storage template. */
	public static final int PT_TLS = 7;

	/** Lower bound of the range reserved for operating system-specific semantics. */
	public static final int PT_LOOS = 0x60000000;
	/** EH frame segment */
	public static final int PT_GNU_EH_FRAME = 0x6474e550;
	/** Upper bound of the range reserved for operating system-specific semantics. */
	public static final int PT_HIOS = 0x6fffffff;
	/** Lower bound of the range reserved for processor-specific semantics. */
	public static final int PT_LOPROC = 0x70000000;
	/** .ARM.exidx segment */
	public static final int PT_ARM_EXIDX = 0x70000001;
	/** Upper bound of the range reserved for processor-specific semantics. */
	public static final int PT_HIPROC = 0x7fffffff;

	/** Elf{32,64}_Phdr#p_type. Kind of segment this element describes. */
	public final int type; // Elf32_Word/Elf64_Word - 4 bytes in both.
	/** Elf{32,64}_Phdr#p_offset. File offset at which the first byte of the segment resides. */
	public final long offset; // Elf32_Off/Elf64_Off - 4 or 8 bytes.
	/** Elf{32,64}_Phdr#p_vaddr. Virtual address at which the first byte of the segment resides in memory. */
	public final long virtual_address; // Elf32_Addr/Elf64_Addr - 4 or 8 bytes.
	/** Reserved for the physical address of the segment on systems where physical addressing is relevant. */
	public final long physical_address; // Elf32_addr/Elf64_Addr - 4 or 8 bytes.

	/** Elf{32,64}_Phdr#p_filesz. File image size of segment in bytes, may be 0. */
	public final long file_size; // Elf32_Word/Elf64_Xword -
	/** Elf{32,64}_Phdr#p_memsz. Memory image size of segment in bytes, may be 0. */
	public final long mem_size; // Elf32_Word
	/**
	 * Flags relevant to this segment. Values for flags are defined in ELFSectionHeader.
	 */
	public final int flags; // Elf32_Word
	public final long alignment; // Elf32_Word

	private MemoizedObject<String> ptInterpreter;
	private MemoizedObject<PtLoadData> ptLoad;
	private MemoizedObject<GnuEhFrameHeader> ehFrameHeader;
	private MemoizedObject<ElfDynamicStructure> dynamicStructure;
	private MemoizedObject<ArmExIdx> arm_exidx;

	ElfSegment(final ElfParser parser, final long offset) {
		parser.seek(offset);
		if (parser.elfFile.objectSize == ElfFile.CLASS_32) {
			// typedef struct {
			// Elf32_Word p_type;
			// Elf32_Off p_offset;
			// Elf32_Addr p_vaddr;
			// Elf32_Addr p_paddr;
			// Elf32_Word p_filesz;
			// Elf32_Word p_memsz;
			// Elf32_Word p_flags;
			// Elf32_Word p_align;
			// } Elf32_Phdr;
			type = parser.readInt();
			this.offset = parser.readInt();
			virtual_address = parser.readInt();
			physical_address = parser.readInt();
			file_size = parser.readInt();
			mem_size = parser.readInt();
			flags = parser.readInt();
			alignment = parser.readInt();
		} else {
			// typedef struct {
			// Elf64_Word p_type;
			// Elf64_Word p_flags;
			// Elf64_Off p_offset;
			// Elf64_Addr p_vaddr;
			// Elf64_Addr p_paddr;
			// Elf64_Xword p_filesz;
			// Elf64_Xword p_memsz;
			// Elf64_Xword p_align;
			// } Elf64_Phdr;
			type = parser.readInt();
			flags = parser.readInt();
			this.offset = parser.readLong();
			virtual_address = parser.readLong();
			physical_address = parser.readLong();
			file_size = parser.readLong();
			mem_size = parser.readLong();
			alignment = parser.readLong();
		}

		switch (type) {
		case PT_INTERP:
			ptInterpreter = new MemoizedObject<String>() {
				@Override
				protected String computeValue() throws ElfException {
					parser.seek(ElfSegment.this.offset);
					StringBuilder buffer = new StringBuilder();
					int b;
					while ((b = parser.readUnsignedByte()) != 0)
						buffer.append((char) b);
					return buffer.toString();
				}
			};
			break;
		case PT_LOAD:
			ptLoad = new MemoizedObject<PtLoadData>() {
				@Override
				protected PtLoadData computeValue() throws ElfException {
					parser.seek(ElfSegment.this.offset);
					ByteBuffer buffer = parser.readBuffer((int) file_size);
					return new PtLoadData(buffer);
				}
			};
			break;
        case PT_DYNAMIC:
            dynamicStructure = new MemoizedObject<ElfDynamicStructure>() {
                @Override
                protected ElfDynamicStructure computeValue() throws ElfException, IOException {
                    return new ElfDynamicStructure(parser, parser.virtualMemoryAddrToFileOffset(virtual_address), (int) mem_size);
                }
            };
            break;
		case PT_GNU_EH_FRAME:
			ehFrameHeader = new MemoizedObject<GnuEhFrameHeader>() {
				@Override
				protected GnuEhFrameHeader computeValue() throws ElfException, IOException {
					return new GnuEhFrameHeader(parser, parser.virtualMemoryAddrToFileOffset(virtual_address), (int) mem_size);
				}
			};
			break;
		case PT_ARM_EXIDX:
			arm_exidx = new MemoizedObject<ArmExIdx>() {
				@Override
				protected ArmExIdx computeValue() throws ElfException {
					parser.seek(ElfSegment.this.offset);
					ByteBuffer buffer = parser.readBuffer((int) file_size);
					return new ArmExIdx(ElfSegment.this.virtual_address, buffer);
				}
			};
            break;
		}
	}

	public static final int PF_R = 4;
	public static final int PF_W = 2;
	public static final int PF_X = 1;

	@Override
	public String toString() {
		String typeString;
		switch (type) {
		case PT_NULL:
			typeString = "PT_NULL";
			break;
		case PT_LOAD:
			typeString = "PT_LOAD";
			break;
		case PT_DYNAMIC:
			typeString = "PT_DYNAMIC";
			break;
		case PT_INTERP:
			typeString = "PT_INTERP";
			break;
		case PT_NOTE:
			typeString = "PT_NOTE";
			break;
		case PT_SHLIB:
			typeString = "PT_SHLIB";
			break;
		case PT_PHDR:
			typeString = "PT_PHDR";
			break;
		case PT_GNU_EH_FRAME:
			typeString = "PT_GNU_EH_FRAME";
			break;
		case PT_ARM_EXIDX:
			typeString = "PT_ARM_EXIDX";
			break;
		default:
			typeString = "0x" + Long.toHexString(type);
			break;
		}

		StringBuilder pFlagsString = new StringBuilder();
		if ((flags & PF_R) != 0) {
			pFlagsString.append("read");
		}
		if ((flags & PF_W) != 0) {
			if (pFlagsString.length() > 0) {
				pFlagsString.append("|");
			}
			pFlagsString.append("write");
		}
		if ((flags & PF_X) != 0) {
			if (pFlagsString.length() > 0) {
				pFlagsString.append("|");
			}
			pFlagsString.append("execute");
		}
		if (pFlagsString.length() == 0) {
			pFlagsString.append("0x").append(Long.toHexString(flags));
		}

		return "ElfProgramHeader[p_type=" + typeString + ", p_filesz=" + file_size + ", p_memsz=" + mem_size + ", p_flags=" + pFlagsString + ", p_align="
				+ alignment + ", range=[0x" + Long.toHexString(virtual_address) + "-0x" + Long.toHexString(virtual_address + mem_size) + "]]";
	}

	/** Only for {@link #PT_INTERP} headers. */
	public String getInterpreter() throws IOException {
		return (ptInterpreter == null) ? null : ptInterpreter.getValue();
	}

	public PtLoadData getPtLoadData() throws IOException {
		return ptLoad == null ? null : ptLoad.getValue();
	}

	public ElfDynamicStructure getDynamicStructure() throws IOException {
	    return dynamicStructure == null ? null : dynamicStructure.getValue();
    }

    public MemoizedObject<GnuEhFrameHeader> getEhFrameHeader() {
		return ehFrameHeader;
	}

    public MemoizedObject<ArmExIdx> getARMExIdxData() {
		return arm_exidx;
	}
}
