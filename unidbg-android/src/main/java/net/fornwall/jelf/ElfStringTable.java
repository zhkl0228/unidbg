package net.fornwall.jelf;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;

import java.nio.ByteBuffer;

final class ElfStringTable {

	/** The string table data. */
	private final ByteBuffer buffer;

	/** Reads all the strings from [offset, length]. */
	ElfStringTable(ElfParser parser, long offset, int length) throws ElfException {
		parser.seek(offset);
		buffer = parser.readBuffer(length);
	}

	private final ByteOutputStream baos = new ByteOutputStream(16);

	String get(int index) {
		buffer.position(index);
		baos.reset();
		byte b;
		while((b = buffer.get()) != 0) {
			baos.write(b);
		}
		return baos.toString();
	}
}
