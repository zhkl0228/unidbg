package net.fornwall.jelf;

import java.nio.ByteBuffer;
import java.util.Iterator;

public class AndroidRelocation implements Iterable<MemoizedObject<ElfRelocation>> {

    private final ElfParser parser;
    private final SymbolLocator symtab;
    private final ByteBuffer androidRelData;
    private final boolean rela;

    AndroidRelocation(ElfParser parser, SymbolLocator symtab, ByteBuffer androidRelData, boolean rela) {
        this.parser = parser;
        this.symtab = symtab;
        this.androidRelData = androidRelData;
        this.rela = rela;
    }

    @Override
    public Iterator<MemoizedObject<ElfRelocation>> iterator() {
        return new AndroidRelocationIterator(parser.elfFile.objectSize, symtab, androidRelData, rela);
    }
}
