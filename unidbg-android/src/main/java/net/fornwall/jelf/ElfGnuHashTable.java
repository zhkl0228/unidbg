package net.fornwall.jelf;

import java.io.IOException;

class ElfGnuHashTable implements HashTable {

    private interface HashChain {
        int chain(int index);
    }

    private final int nbucket;
    private final int maskwords;
    private final int shift2;

    private final long[] bloom_filters;
    private final int[] buckets;
    private final HashChain chains;

    private final int bloom_mask_bits;

    ElfGnuHashTable(final ElfParser parser, long offset) {
        parser.seek(offset);
        nbucket = parser.readInt();
        int symndx = parser.readInt();
        int gnu_maskwords_ = parser.readInt();
        shift2 = parser.readInt();

        bloom_filters = new long[gnu_maskwords_];
        for (int i = 0; i < bloom_filters.length; i++) {
            bloom_filters[i] = parser.readIntOrLong();
        }

        buckets = new int[nbucket];
        for (int i = 0; i < nbucket; i++) {
            buckets[i] = parser.readInt();
        }

        final long chain_base = offset + 16 + gnu_maskwords_ * (parser.elfFile.objectSize == ElfFile.CLASS_32 ? 4 : 8) + nbucket * 4 - symndx * 4;
        chains = new HashChain() {
            @Override
            public int chain(int index) {
                parser.seek(chain_base + index * 4);
                return parser.readInt();
            }
        };

        maskwords = gnu_maskwords_ - 1;
        bloom_mask_bits = parser.elfFile.objectSize == ElfFile.CLASS_32 ? 32 : 64;
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
        final long h2 = hash >> shift2;

        long word_num = (hash / bloom_mask_bits) & maskwords;
        long bloom_word = bloom_filters[(int) word_num];

        // test against bloom filter
        if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
            return null;
        }

        // bloom test says "probably yes"...
        int n = buckets[(int) (hash % nbucket)];
        if (n == 0) {
            return null;
        }

        do {
            ElfSymbol symbol = symbolStructure.getELFSymbol(n);
            if (symbolName.equals(symbol.getName())) {
                return symbol;
            }
        } while ((chains.chain(n++) & 1) == 0);

        return null;
    }

    private static long elf_hash(String name) {
        long h = 5381;

        for(char c : name.toCharArray()) {
            h += (h << 5) + c; // h*33 + c = h + h * 32 + c = h + h << 5 + c
        }
        return h & 0xffffffffL;
    }

    @Override
    public int getNumBuckets() {
        return nbucket;
    }
}
