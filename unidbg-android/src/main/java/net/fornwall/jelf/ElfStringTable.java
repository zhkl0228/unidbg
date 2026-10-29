package net.fornwall.jelf;


import java.nio.ByteBuffer;

final class ElfStringTable {

	/** The string table data. */
	private final ByteBuffer buffer;

	/** Reads all the strings from [offset, length]. */
	ElfStringTable(ElfParser parser, long offset, int length) throws ElfException {
		parser.seek(offset);
		buffer = parser.readBuffer(length);
	}

	private byte[] scratch = new byte[16];

	String get(int index) {
		buffer.position(index);
		while (buffer.get() != 0) {
			// Scan first, then bulk-copy without a synchronized write per byte.
		}
		int end = buffer.position();
		int length = end - index - 1;
		if (scratch.length < length) {
			scratch = new byte[Math.max(scratch.length << 1, length)];
		}
		buffer.position(index);
		buffer.get(scratch, 0, length);
		buffer.position(end);
		return new String(scratch, 0, length);
	}
}
