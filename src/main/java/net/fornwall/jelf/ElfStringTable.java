package net.fornwall.jelf;

import java.io.IOException;

final class ElfStringTable {

	/** The string table data. */
	private final byte data[];

	/** Reads all the strings from [offset, length]. */
	ElfStringTable(ElfParser parser, long offset, int length) throws ElfException, IOException {
		parser.seek(offset);
		data = new byte[length];
		int bytesRead = parser.read(data);
		if (bytesRead != length)
			throw new ElfException("Error reading string table (read " + bytesRead + "bytes - expected to " + "read " + data.length + "bytes)");
	}

	String get(int index) {
		int endPtr = index;
		while (data[endPtr] != '\0')
			endPtr++;
		return new String(data, index, endPtr - index);
	}
}
