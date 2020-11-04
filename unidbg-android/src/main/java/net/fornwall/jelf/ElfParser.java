package net.fornwall.jelf;

import java.io.IOException;
import java.nio.ByteBuffer;

/** Package internal class used for parsing ELF files. */
class ElfParser implements ElfDataIn {

	final ElfFile elfFile;
	private final ByteBuffer fsFile;

	ElfParser(ElfFile elfFile, ByteBuffer fsFile) {
		this.elfFile = elfFile;
		this.fsFile = fsFile;
	}

	void seek(long offset) {
		fsFile.position((int) offset);
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
		return ((((long) byteSwap((int) arg)) << 32) | (((long) byteSwap((int) (arg >>> 32)))));
	}

	@Override
	public short readUnsignedByte() {
		int val = fsFile.get() & 0xff;
		return (short) val;
	}

	@Override
	public short readShort() throws ElfException {
		int ch1 = readUnsignedByte();
		int ch2 = readUnsignedByte();
		short val = (short) ((ch1 << 8) + (ch2));
		if (elfFile.encoding == ElfFile.DATA_LSB) val = byteSwap(val);
		return val;
	}

	@Override
	public int readInt() throws ElfException {
		int ch1 = readUnsignedByte();
		int ch2 = readUnsignedByte();
		int ch3 = readUnsignedByte();
		int ch4 = readUnsignedByte();
		int val = ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4));

		if (elfFile.encoding == ElfFile.DATA_LSB) {
			val = byteSwap(val);
		}
		return val;
	}

	@Override
	public long readLong() {
		int ch1 = readUnsignedByte();
		int ch2 = readUnsignedByte();
		int ch3 = readUnsignedByte();
		int ch4 = readUnsignedByte();
		int val1 = ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4));
		int ch5 = readUnsignedByte();
		int ch6 = readUnsignedByte();
		int ch7 = readUnsignedByte();
		int ch8 = readUnsignedByte();
		int val2 = ((ch5 << 24) + (ch6 << 16) + (ch7 << 8) + (ch8));

		long val = ((long) (val1) << 32) + (val2 & 0xFFFFFFFFL);
		if (elfFile.encoding == ElfFile.DATA_LSB) {
			val = byteSwap(val);
		}
		return val;
	}

	/** Read four-byte int or eight-byte long depending on if {@link ElfFile#objectSize}. */
	long readIntOrLong() {
		return elfFile.objectSize == ElfFile.CLASS_32 ? readInt() : readLong();
	}

	/** Returns a big-endian unsigned representation of the int. */
	@SuppressWarnings("unused")
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

	int read(byte[] data) {
		fsFile.get(data);
		return data.length;
	}

	ByteBuffer readBuffer(int length) {
		int limit = fsFile.limit();
		try {
			fsFile.limit(fsFile.position() + length);
			return fsFile.slice();
		} finally {
			fsFile.limit(limit);
		}
	}

}
