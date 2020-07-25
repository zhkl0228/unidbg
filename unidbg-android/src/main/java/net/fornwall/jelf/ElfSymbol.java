package net.fornwall.jelf;

import java.io.IOException;

/**
 * Class corresponding to the Elf32_Sym/Elf64_Sym struct.
 */
public final class ElfSymbol {

	private static final int SHN_UNDEF = 0;

	/** Binding specifying that local symbols are not visible outside the object file that contains its definition. */
	public static final int BINDING_LOCAL = 0;
	/** Binding specifying that global symbols are visible to all object files being combined. */
	public static final int BINDING_GLOBAL = 1;
	/** Binding specifying that the symbol resembles a global symbol, but has a lower precedence. */
	public static final int BINDING_WEAK = 2;
	/** Lower bound binding values reserved for processor specific semantics. */
	public static final int BINDING_LOPROC = 13;
	/** Upper bound binding values reserved for processor specific semantics. */
	public static final int BINDING_HIPROC = 15;

	/** Type specifying that the symbol is unspecified. */
	public static final byte STT_NOTYPE = 0;
	/** Type specifying that the symbol is associated with an object. */
	public static final byte STT_OBJECT = 1;
	/** Type specifying that the symbol is associated with a function or other executable code. */
	public static final byte STT_FUNC = 2;
	/**
	 * Type specifying that the symbol is associated with a section. Symbol table entries of this type exist for
	 * relocation and normally have the binding BINDING_LOCAL.
	 */
	public static final byte STT_SECTION = 3;
	/** Type defining that the symbol is associated with a file. */
	public static final byte STT_FILE = 4;
	/** The symbol labels an uninitialized common block. */
	public static final byte STT_COMMON = 5;
	/** The symbol specifies a Thread-Local Storage entity. */
	public static final byte STT_TLS = 6;

	/** Lower bound for range reserved for operating system-specific semantics. */
	public static final byte STT_LOOS = 10;
	/** Upper bound for range reserved for operating system-specific semantics. */
	public static final byte STT_HIOS = 12;
	/** Lower bound for range reserved for processor-specific semantics. */
	public static final byte STT_LOPROC = 13;
	/** Upper bound for range reserved for processor-specific semantics. */
	public static final byte STT_HIPROC = 15;

	/**
	 * Index into the symbol string table that holds the character representation of the symbols. 0 means the symbol has
	 * no character name.
	 */
	private final int name_ndx; // Elf32_Word
	/** Value of the associated symbol. This may be a relativa address for .so or absolute address for other ELFs. */
	public final long value; // Elf32_Addr
	/** Size of the symbol. 0 if the symbol has no size or the size is unknown. */
	public final long size; // Elf32_Word
	/** Specifies the symbol type and binding attributes. */
	private final short info; // unsigned char
	/** Currently holds the value of 0 and has no meaning. */
	public final short other; // unsigned char
	/**
	 * Index to the associated section header. This value will need to be read as an unsigned short if we compare it to
	 * ELFSectionHeader.NDX_LORESERVE and ELFSectionHeader.NDX_HIRESERVE.
	 */
	public final short section_header_ndx; // Elf32_Half

	private final int section_type;

	/** Offset from the beginning of the file to this symbol. */
	public final long offset;

	private final ElfFile elfHeader;

	ElfSymbol(ElfParser parser, long offset, int section_type) {
		this.elfHeader = parser.elfFile;
		parser.seek(offset);
		this.offset = offset;
		if (parser.elfFile.objectSize == ElfFile.CLASS_32) {
			name_ndx = parser.readInt();
			value = parser.readInt();
			size = parser.readInt();
			info = parser.readUnsignedByte();
			other = parser.readUnsignedByte();
			section_header_ndx = parser.readShort();
		} else {
			name_ndx = parser.readInt();
			info = parser.readUnsignedByte();
			other = parser.readUnsignedByte();
			section_header_ndx = parser.readShort();
			value = parser.readLong();
			size = parser.readLong();
		}

		this.section_type = section_type;

		switch (getType()) {
		case STT_NOTYPE:
			break;
		case STT_OBJECT:
			break;
		case STT_FUNC:
			break;
		case STT_SECTION:
			break;
		case STT_FILE:
			break;
		case STT_LOPROC:
			break;
		case STT_HIPROC:
			break;
		default:
			break;
		}
	}

	private ElfStringTable stringTable;

    ElfSymbol setStringTable(ElfStringTable stringTable) {
        this.stringTable = stringTable;
        return this;
    }

    /** Returns the binding for this symbol. */
	public int getBinding() {
		return info >> 4;
	}

	/** Returns the symbol type. */
	public int getType() {
		return info & 0x0F;
	}

	/** Returns the name of the symbol or null if the symbol has no name. */
	public String getName() throws ElfException, IOException {
		// Check to make sure this symbol has a name.
		if (name_ndx == 0)
			return null;

		// Retrieve the name of the symbol from the correct string table.
		String symbol_name = null;
        if (stringTable != null) {
            symbol_name = stringTable.get(name_ndx);
        } else if (section_type == ElfSection.SHT_SYMTAB) {
			symbol_name = elfHeader.getStringTable().get(name_ndx);
		} else if (section_type == ElfSection.SHT_DYNSYM) {
			symbol_name = elfHeader.getDynamicStringTable().get(name_ndx);
		}
		return symbol_name;
	}

	public boolean isUndef() {
		return section_header_ndx == SHN_UNDEF;
	}

	@Override
	public String toString() {
		String typeString;
		switch (getType()) {
		case STT_NOTYPE:
		case STT_OBJECT:
			typeString = "object";
			break;
		case STT_FUNC:
			typeString = "function";
			break;
		case STT_SECTION:
			typeString = "section";
			break;
		case STT_FILE:
			typeString = "file";
			break;
		case STT_LOPROC:
			typeString = "loproc";
			break;
		case STT_HIPROC:
			typeString = "hiproc";
			break;
		default:
			typeString = "???";
			break;
		}

		try {
			return "ElfSymbol[name=" + getName() + ", type=" + typeString + ", size=" + size + "]";
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
