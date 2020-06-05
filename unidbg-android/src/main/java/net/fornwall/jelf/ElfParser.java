package net.fornwall.jelf;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/** Package internal class used for parsing ELF files. */
class ElfParser {

	final ElfFile elfFile;
	private final ByteArrayInputStream fsFile;

	ElfParser(ElfFile elfFile, ByteArrayInputStream fsFile) {
		this.elfFile = elfFile;
		this.fsFile = fsFile;
	}

	void seek(long offset) {
		fsFile.reset();
		if (fsFile.skip(offset) != offset)
			throw new ElfException("seeking outside file");
	}

	/**
	 * Signed byte utility functions used for converting from big-endian (MSB) to little-endian (LSB).
	 */
	short byteSwap(short arg) {
		return (short) ((arg << 8) | ((arg >>> 8) & 0xFF));
	}

	int byteSwap(int arg) {
		return ((byteSwap((short) arg)) << 16) | (((byteSwap((short) (arg >>> 16)))) & 0xFFFF);
	}

	long byteSwap(long arg) {
		return ((((long) byteSwap((int) arg)) << 32) | (((long) byteSwap((int) (arg >>> 32))) & 0xFFFFFFFF));
	}

	short readUnsignedByte() {
		int val = fsFile.read();
		if (val < 0) throw new ElfException("Trying to read outside file");
		return (short) val;
	}

	short readShort() throws ElfException {
		int ch1 = readUnsignedByte();
		int ch2 = readUnsignedByte();
		short val = (short) ((ch1 << 8) + (ch2 << 0));
		if (elfFile.encoding == ElfFile.DATA_LSB) val = byteSwap(val);
		return val;
	}

	int readInt() throws ElfException {
		int ch1 = readUnsignedByte();
		int ch2 = readUnsignedByte();
		int ch3 = readUnsignedByte();
		int ch4 = readUnsignedByte();
		int val = ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));

		if (elfFile.encoding == ElfFile.DATA_LSB) val = byteSwap(val);
		return val;
	}

	long readLong() {
		int ch1 = readUnsignedByte();
		int ch2 = readUnsignedByte();
		int ch3 = readUnsignedByte();
		int ch4 = readUnsignedByte();
		int val1 = ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
		int ch5 = readUnsignedByte();
		int ch6 = readUnsignedByte();
		int ch7 = readUnsignedByte();
		int ch8 = readUnsignedByte();
		int val2 = ((ch5 << 24) + (ch6 << 16) + (ch7 << 8) + (ch8 << 0));

		long val = ((long) (val1) << 32) + (val2 & 0xFFFFFFFFL);
		if (elfFile.encoding == ElfFile.DATA_LSB) val = byteSwap(val);
		return val;
	}

	/** Read four-byte int or eight-byte long depending on if {@link ElfFile#objectSize}. */
	long readIntOrLong() {
		return elfFile.objectSize == ElfFile.CLASS_32 ? readInt() : readLong();
	}

	/** Returns a big-endian unsigned representation of the int. */
	long unsignedByte(int arg) {
		long val;
		if (arg >= 0) {
			val = arg;
		} else {
			val = (unsignedByte((short) (arg >>> 16)) << 16) | ((short) arg);
		}
		return val;
	}

	/**
	 * Find the file offset from a virtual address by looking up the {@link ElfSegment} segment containing the
	 * address and computing the resulting file offset.
	 */
	long virtualMemoryAddrToFileOffset(long address) throws IOException {
		for (int i = 0; i < elfFile.num_ph; i++) {
			ElfSegment ph = elfFile.getProgramHeader(i);
			if (address >= ph.virtual_address && address < (ph.virtual_address + ph.mem_size)) {
				long relativeOffset = address - ph.virtual_address;
				if (relativeOffset >= ph.file_size)
					throw new ElfException("Can not convert virtual memory address " + Long.toHexString(address) + " to file offset -" + " found segment " + ph
							+ " but address maps to memory outside file range");
				return ph.offset + relativeOffset;
			}
		}
		throw new ElfException("Cannot find segment for address " + Long.toHexString(address));
	}

	public int read(byte[] data) throws IOException {
		return fsFile.read(data);
	}

}
