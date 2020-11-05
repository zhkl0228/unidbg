package net.fornwall.jelf;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#dynamic_section
 * 
 * "If an object file participates in dynamic linking, its program header table will have an element of type PT_DYNAMIC. This ``segment'' contains the .dynamic
 * section. A special symbol, _DYNAMIC, labels the section, which contains an array of the following structures."
 * 
 * <pre>
 * typedef struct { Elf32_Sword d_tag; union { Elf32_Word d_val; Elf32_Addr d_ptr; } d_un; } Elf32_Dyn;
 * extern Elf32_Dyn _DYNAMIC[];
 * 
 * typedef struct { Elf64_Sxword d_tag; union { Elf64_Xword d_val; Elf64_Addr d_ptr; } d_un; } Elf64_Dyn;
 * extern Elf64_Dyn _DYNAMIC[];
 * </pre>
 * 
 * <pre>
 * http://www.sco.com/developers/gabi/latest/ch5.dynamic.html:
 * 
 * Name	        		Value		d_un		Executable	Shared Object
 * ----------------------------------------------------------------------
 * DT_NULL	    		0			ignored		mandatory	mandatory
 * DT_NEEDED			1			d_val		optional	optional
 * DT_PLTRELSZ			2			d_val		optional	optional
 * DT_PLTGOT			3			d_ptr		optional	optional
 * DT_HASH				4			d_ptr		mandatory	mandatory
 * DT_STRTAB			5			d_ptr		mandatory	mandatory
 * DT_SYMTAB			6			d_ptr		mandatory	mandatory
 * DT_RELA				7			d_ptr		mandatory	optional
 * DT_RELASZ			8			d_val		mandatory	optional
 * DT_RELAENT			9			d_val		mandatory	optional
 * DT_STRSZ				10			d_val		mandatory	mandatory
 * DT_SYMENT			11			d_val		mandatory	mandatory
 * DT_INIT  			12			d_ptr		optional	optional
 * DT_FINI	    		13			d_ptr		optional	optional
 * DT_SONAME			14			d_val		ignored		optional
 * DT_RPATH*			15			d_val		optional	ignored
 * DT_SYMBOLIC*			16			ignored		ignored		optional
 * DT_REL	    		17			d_ptr		mandatory	optional
 * DT_RELSZ	    		18			d_val		mandatory	optional
 * DT_RELENT			19			d_val		mandatory	optional
 * DT_PLTREL			20			d_val		optional	optional
 * DT_DEBUG	    		21			d_ptr		optional	ignored
 * DT_TEXTREL*			22			ignored		optional	optional
 * DT_JMPREL			23			d_ptr		optional	optional
 * DT_BIND_NOW*			24			ignored		optional	optional
 * DT_INIT_ARRAY		25			d_ptr		optional	optional
 * DT_FINI_ARRAY		26			d_ptr		optional	optional
 * DT_INIT_ARRAYSZ		27			d_val		optional	optional
 * DT_FINI_ARRAYSZ		28			d_val		optional	optional
 * DT_RUNPATH			29			d_val		optional	optional
 * DT_FLAGS				30			d_val		optional	optional
 * DT_ENCODING			32			unspecified	unspecified	unspecified
 * DT_PREINIT_ARRAY		32			d_ptr		optional	ignored
 * DT_PREINIT_ARRAYSZ	33			d_val		optional	ignored
 * DT_LOOS				0x6000000D	unspecified	unspecified	unspecified
 * DT_HIOS				0x6ffff000	unspecified	unspecified	unspecified
 * DT_LOPROC			0x70000000	unspecified	unspecified	unspecified
 * DT_HIPROC			0x7fffffff	unspecified	unspecified	unspecified
 * </pre>
 */
public class ElfDynamicStructure {

	private static final Log log = LogFactory.getLog(ElfDynamicStructure.class);

	private static final int DT_NULL = 0;
	private static final int DT_NEEDED = 1;
	private static final int DT_PLTRELSZ = 2;
	public static final int DT_PLTGOT = 3;
	private static final int DT_HASH = 4;
	/** DT_STRTAB entry holds the address, not offset, of the dynamic string table. */
	private static final int DT_STRTAB = 5;
	private static final int DT_SYMTAB = 6;
	public static final int DT_RELA = 7;
	public static final int DT_RELASZ = 8;
	public static final int DT_RELAENT = 9;
	/** The size in bytes of the {@link #DT_STRTAB} string table. */
	private static final int DT_STRSZ = 10;
	private static final int DT_SYMENT = 11;
	private static final int DT_INIT = 12;
	public static final int DT_FINI = 13;
	private static final int DT_SONAME = 14;
	public static final int DT_RPATH = 15;
	private static final int DT_REL = 17;
	private static final int DT_RELSZ = 18;
	private static final int DT_RELENT = 19;
    private static final int DT_JMPREL = 23;
	private static final int DT_INIT_ARRAY = 25;
	private static final int DT_INIT_ARRAYSZ = 27;
	public static final int DT_RUNPATH = 29;
	private static final int DT_PREINIT_ARRAY = 32;
	private static final int DT_PREINIT_ARRAYSZ = 33;
	private static final int DT_VERSYM = 0x6ffffff0;
	private static final int DT_GNU_HASH = 0x6ffffef5;
	private static final int DT_RELACOUNT = 0x6ffffff9;
	private static final int DT_RELCOUNT = 0x6ffffffa;
	private static final int DT_FLAGS_1 = 0x6ffffffb;
	private static final int DT_VERDEF = 0x6ffffffc; /* Address of version definition */
	private static final int DT_VERDEFNUM = 0x6ffffffd; /* Number of version definitions */
	private static final int DT_VERNEEDED = 0x6ffffffe;
	private static final int DT_VERNEEDNUM = 0x6fffffff;

	private static final int DT_ANDROID_REL = 0x6000000f;
	private static final int DT_ANDROID_RELSZ = 0x60000010;
	private static final int DT_ANDROID_RELA = 0x60000011;
	private static final int DT_ANDROID_RELASZ = 0x60000012;

	/** Some values of {@link #DT_FLAGS_1}. */
	public static final int DF_1_NOW = 0x00000001; /* Set RTLD_NOW for this object. */
	public static final int DF_1_GLOBAL = 0x00000002; /* Set RTLD_GLOBAL for this object. */
	public static final int DF_1_GROUP = 0x00000004; /* Set RTLD_GROUP for this object. */
	public static final int DF_1_NODELETE = 0x00000008; /* Set RTLD_NODELETE for this object. */

	/** For the {@link #DT_STRTAB}. Mandatory. */
	private long dt_strtab_offset;
	/** For the {@link #DT_STRSZ}. Mandatory. */
	private int dt_strtab_size;

	private MemoizedObject<ElfStringTable> dtStringTable;
	private final int[] dtNeeded;
	private final int soName;
	private final int init;
	private long initArrayOffset, preInitArrayOffset;
	private int initArraySize, preInitArraySize;
	private MemoizedObject<ElfInitArray> initArray, preInitArray;
	private MemoizedObject<ElfSymbolStructure> symbolStructure;

	private int symbolEntrySize;
	private long symbolOffset;

	private long hashOffset, gnuHashOffset;

	private long relOffset;
	private int relSize, relEntrySize;

    private long pltRelOffset;
    private int pltRelSize;

    private long androidRelOffset, androidRelAOffset;
    private int androidRelSize, androidRelASize;

    private MemoizedObject<ElfRelocation>[] rel, pltRel;
    private MemoizedObject<AndroidRelocation> androidRelocation;

	ElfDynamicStructure(final ElfParser parser, long offset, int size) throws IOException {
		parser.seek(offset);
		int numEntries = size / (parser.elfFile.objectSize == ElfFile.CLASS_32 ? 8 : 16);

		List<Integer> dtNeededList = new ArrayList<>();
		// Except for the DT_NULL element at the end of the array, and the relative order of DT_NEEDED elements, entries
		// may appear in any order. So important to use lazy evaluation to only evaluating e.g. DT_STRTAB after the
		// necessary DT_STRSZ is read.
		int soName = -1;
		int init = 0;
		loop: for (int i = 0; i < numEntries; i++) {
			long d_tag = parser.readIntOrLong();
			final long d_val_or_ptr = parser.readIntOrLong();
			switch ((int) d_tag) {
			case DT_NULL:
				// A DT_NULL element ends the array (may be following DT_NULL values, but no need to look at them).
				break loop;
			case DT_NEEDED:
				dtNeededList.add((int) d_val_or_ptr);
				break;
			case DT_STRTAB:
				dt_strtab_offset = d_val_or_ptr;
				break;
			case DT_STRSZ:
				if (d_val_or_ptr > Integer.MAX_VALUE) throw new ElfException("Too large DT_STRSZ: " + d_val_or_ptr);
				dt_strtab_size = (int) d_val_or_ptr;
				break;
			case DT_SONAME:
				soName = (int) d_val_or_ptr;
				break;
			case DT_INIT:
				init = (int) d_val_or_ptr;
				break;
			case DT_INIT_ARRAY:
				initArrayOffset = d_val_or_ptr;
				break;
			case DT_INIT_ARRAYSZ:
				initArraySize = (int) d_val_or_ptr;
				break;
			case DT_PREINIT_ARRAY:
				preInitArrayOffset = d_val_or_ptr;
				break;
			case DT_PREINIT_ARRAYSZ:
				preInitArraySize = (int) d_val_or_ptr;
				break;
			case DT_SYMENT:
				symbolEntrySize = (int) d_val_or_ptr;
				break;
			case DT_SYMTAB:
				symbolOffset = d_val_or_ptr;
				break;
			case DT_HASH:
				hashOffset = d_val_or_ptr;
				break;
			case DT_GNU_HASH:
				gnuHashOffset = d_val_or_ptr;
				break;
			case DT_RELA:
            case DT_REL:
                relOffset = d_val_or_ptr;
                break;
			case DT_RELASZ:
            case DT_RELSZ:
                relSize = (int) d_val_or_ptr;
                break;
			case DT_RELAENT:
            case DT_RELENT:
                relEntrySize = (int) d_val_or_ptr;
                break;
            case DT_PLTRELSZ:
                pltRelSize = (int) d_val_or_ptr;
                break;
            case DT_JMPREL:
                pltRelOffset = d_val_or_ptr;
                break;
			case DT_ANDROID_RELASZ:
				androidRelASize = (int) d_val_or_ptr;
				break;
			case DT_ANDROID_RELSZ:
				androidRelSize = (int) d_val_or_ptr;
				break;
			case DT_ANDROID_RELA:
				androidRelAOffset = d_val_or_ptr;
				break;
			case DT_ANDROID_REL:
				androidRelOffset = d_val_or_ptr;
				break;
			case DT_VERSYM:
			case DT_RELACOUNT:
			case DT_RELCOUNT:
			case DT_FLAGS_1:
			case DT_VERDEF:
			case DT_VERDEFNUM:
			case DT_VERNEEDED:
			case DT_VERNEEDNUM:
				break;
			default:
				boolean androidTag = (d_tag & 0x60000000) != 0;
				if (androidTag) {
					log.warn("Unsupported android tag: 0x" + Long.toHexString(d_tag));
				}
				break;
			}
		}

		if (dt_strtab_size > 0) {
			dtStringTable = new MemoizedObject<ElfStringTable>() {
				@Override
				protected ElfStringTable computeValue() throws ElfException, IOException {
					return new ElfStringTable(parser, parser.virtualMemoryAddrToFileOffset(dt_strtab_offset), dt_strtab_size);
				}
			};
		}

		final MemoizedObject<HashTable> hashTable;
		if (hashOffset > 0) {
			hashTable = new MemoizedObject<HashTable>() {
				@Override
				protected HashTable computeValue() throws ElfException, IOException {
					return new ElfHashTable(parser, parser.virtualMemoryAddrToFileOffset(hashOffset), -1);
				}
			};
		} else if(gnuHashOffset > 0) {
			hashTable = new MemoizedObject<HashTable>() {
				@Override
				protected HashTable computeValue() throws ElfException, IOException {
					return new ElfGnuHashTable(parser, parser.virtualMemoryAddrToFileOffset(gnuHashOffset));
				}
			};
		} else {
			hashTable = null;
		}

		if (symbolOffset > 0) {
			symbolStructure = new MemoizedObject<ElfSymbolStructure>() {
				@Override
				protected ElfSymbolStructure computeValue() throws ElfException, IOException {
					return new ElfSymbolStructure(parser, parser.virtualMemoryAddrToFileOffset(symbolOffset), symbolEntrySize, dtStringTable, hashTable);
				}
			};
		}

        if (relOffset > 0) {
            int num_entries = relSize / relEntrySize;
            rel = MemoizedObject.uncheckedArray(num_entries);
            final long fileOffset = parser.virtualMemoryAddrToFileOffset(relOffset);
            for (int i = 0; i < num_entries; i++) {
                final long relocationOffset = fileOffset + (i * relEntrySize);
                rel[i] = new MemoizedObject<ElfRelocation>() {
                    @Override
                    public ElfRelocation computeValue() throws IOException {
                        return new ElfRelocation(parser, relocationOffset, relEntrySize, symbolStructure.getValue());
                    }
                };
            }
        }

        if (pltRelOffset > 0) {
            int num_entries = pltRelSize / relEntrySize;
            pltRel = MemoizedObject.uncheckedArray(num_entries);
            final long fileOffset = parser.virtualMemoryAddrToFileOffset(pltRelOffset);
            for (int i = 0; i < num_entries; i++) {
                final long relocationOffset = fileOffset + (i * relEntrySize);
                pltRel[i] = new MemoizedObject<ElfRelocation>() {
                    @Override
                    public ElfRelocation computeValue() throws IOException {
                        return new ElfRelocation(parser, relocationOffset, relEntrySize, symbolStructure.getValue());
                    }
                };
            }
        }

		if (androidRelOffset > 0) {
			assert symbolStructure != null;
			androidRelocation = new MemoizedObject<AndroidRelocation>() {
				@Override
				protected AndroidRelocation computeValue() throws ElfException, IOException {
					parser.seek(parser.virtualMemoryAddrToFileOffset(androidRelOffset));
					byte[] magic = new byte[4];
					parser.read(magic);
					if (androidRelSize >= 4 && "APS2".equals(new String(magic))) {
						ByteBuffer androidRelData = parser.readBuffer(androidRelSize - 4);
						return new AndroidRelocation(parser, symbolStructure.getValue(), androidRelData, false);
					} else {
						throw new IllegalStateException("bad android relocation header.");
					}
				}
			};
		} else if (androidRelAOffset > 0) {
			assert symbolStructure != null;
			androidRelocation = new MemoizedObject<AndroidRelocation>() {
				@Override
				protected AndroidRelocation computeValue() throws ElfException, IOException {
					parser.seek(parser.virtualMemoryAddrToFileOffset(androidRelAOffset));
					byte[] magic = new byte[4];
					parser.read(magic);
					if (androidRelASize >= 4 && "APS2".equals(new String(magic))) {
						ByteBuffer androidRelData = parser.readBuffer(androidRelASize - 4);
						return new AndroidRelocation(parser, symbolStructure.getValue(), androidRelData, true);
					} else {
						throw new IllegalStateException("bad android relocation header.");
					}
				}
			};
		}

		if (initArraySize > 0) {
			initArray = new MemoizedObject<ElfInitArray>() {
				@Override
				protected ElfInitArray computeValue() throws ElfException, IOException {
					return new ElfInitArray(parser, parser.virtualMemoryAddrToFileOffset(initArrayOffset), initArraySize);
				}
			};
		}

		if (preInitArraySize > 0) {
			preInitArray = new MemoizedObject<ElfInitArray>() {
				@Override
				protected ElfInitArray computeValue() throws ElfException, IOException {
					return new ElfInitArray(parser, parser.virtualMemoryAddrToFileOffset(preInitArrayOffset), preInitArraySize);
				}
			};
		}

		dtNeeded = new int[dtNeededList.size()];
		for (int i = 0, len = dtNeeded.length; i < len; i++) {
			dtNeeded[i] = dtNeededList.get(i);
		}

		this.soName = soName;
		this.init = init;
	}

	public String getSOName(String fileName) throws IOException {
		ElfStringTable stringTable = dtStringTable.getValue();
		return soName == -1 ? fileName : stringTable.get(soName);
	}

	public int getInit() {
		return init;
	}

	public List<String> getNeededLibraries() throws ElfException, IOException {
		List<String> result = new ArrayList<>();
		ElfStringTable stringTable = dtStringTable.getValue();
		for (int needed : dtNeeded) {
			result.add(stringTable.get(needed));
		}
		return result;
	}

	public long getInitArrayOffset() {
		return initArrayOffset;
	}

	public long getPreInitArrayOffset() {
		return preInitArrayOffset;
	}

	public int getInitArraySize() {
		return initArraySize;
	}

	public int getPreInitArraySize() {
		return preInitArraySize;
	}

	public ElfInitArray getInitArray() throws IOException {
		return initArray == null ? null : initArray.getValue();
	}

	public ElfInitArray getPreInitArray() throws IOException {
		return preInitArray == null ? null : preInitArray.getValue();
	}

	public ElfSymbolStructure getSymbolStructure() throws IOException {
		return symbolStructure.getValue();
	}

	public Collection<MemoizedObject<ElfRelocation>> getRelocations() throws IOException {
        List<MemoizedObject<ElfRelocation>> list = new ArrayList<>();
		if (androidRelocation != null) {
			for (MemoizedObject<ElfRelocation> elfRelocationMemoizedObject : androidRelocation.getValue()) {
				list.add(elfRelocationMemoizedObject);
			}
		}
        if (rel != null) {
            Collections.addAll(list, rel);
        }
        if (pltRel != null) {
            Collections.addAll(list, pltRel);
        }
        return list;
    }

	@Override
	public String toString() {
		return "ElfDynamicStructure[]";
	}
}
