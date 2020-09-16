package net.fornwall.jelf;

import java.io.IOException;

class ElfHashTable implements HashTable {

	/**
	 * Returns the ELFSymbol that has the specified name or null if no symbol with that name exists. NOTE: Currently
	 * this method does not work and will always return null.
	 */
	private final int num_buckets;

	// These could probably be memoized.
	private final int[] buckets;
	private final int[] chains;

	ElfHashTable(ElfParser parser, long offset, int length) {
		parser.seek(offset);
		num_buckets = parser.readInt();
        int num_chains = parser.readInt();

		buckets = new int[num_buckets];
		chains = new int[num_chains];
		// Read the bucket data.
		for (int i = 0; i < num_buckets; i++) {
			buckets[i] = parser.readInt();
		}

		// Read the chain data.
		for (int i = 0; i < num_chains; i++) {
			chains[i] = parser.readInt();
		}

		// Make sure that the amount of bytes we were supposed to read
		// was what we actually read.
		int actual = num_buckets * 4 + num_chains * 4 + 8;
		if (length != -1 && length != actual) {
			throw new ElfException("Error reading string table (read " + actual + "bytes, expected to " + "read " + length + "bytes).");
		}
	}

	private static long elf_hash(String name) {
		long h = 0, g;

		for(char c : name.toCharArray()) {
			h = (h << 4) + c;
			g = h & 0xf0000000L;
			h ^= g;
			h ^= g >> 24;
		}
		return h;
	}

	/**
	 * This method doesn't work every time and is unreliable. Use ELFSection.getELFSymbol(String) to retrieve symbols by
	 * name. NOTE: since this method is currently broken it will always return null.
	 */
	@Override
	public ElfSymbol getSymbol(ElfSymbolStructure symbolStructure, String symbolName) throws IOException {
		if (symbolName == null) {
			return null;
		}

		final long hash = elf_hash(symbolName);

		int index = buckets[(int)hash % num_buckets];
		while(index != 0) {
			ElfSymbol symbol = symbolStructure.getELFSymbol(index);
			if (symbolName.equals(symbol.getName())) {
				return symbol;
			}
			index = chains[index];
		}
		return null;
	}

	@Override
	public int getNumBuckets() {
		return num_buckets;
	}
}
