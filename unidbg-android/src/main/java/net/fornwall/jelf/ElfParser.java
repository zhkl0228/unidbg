package net.fornwall.jelf;

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
