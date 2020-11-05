package net.fornwall.jelf;

import java.io.IOException;
import java.util.Objects;

public class ElfRelocation implements Cloneable {

    private final int objectSize;
    private final SymbolLocator symtab;

    long offset;
    long info;
    long addend;

    private final boolean android;

    ElfRelocation(ElfParser parser, long offset, long entry_size, SymbolLocator symtab) {
        this.objectSize = parser.elfFile.objectSize;
        this.symtab = symtab;
        this.android = false;

        parser.seek(offset);

        if (parser.elfFile.objectSize == ElfFile.CLASS_32) {
            this.offset = parser.readInt() & 0xffffffffL;
            this.info = parser.readInt();
            this.addend = entry_size >= 12 ? parser.readInt() : 0;
        } else {
            this.offset = parser.readLong();
            this.info = parser.readLong();
            this.addend = entry_size >= 24 ? parser.readLong() : 0;
        }
    }

    @Override
    public ElfRelocation clone() throws CloneNotSupportedException {
        return (ElfRelocation) super.clone();
    }

    ElfRelocation(int objectSize, SymbolLocator symtab) {
        this.objectSize = objectSize;
        this.symtab = symtab;
        this.android = true;
    }

    public long offset() {
        return offset;
    }

    private ElfSymbol symbol;

    public ElfSymbol symbol() throws IOException {
        if (symbol == null) {
            symbol = symtab.getELFSymbol(sym());
        }
        return symbol;
    }

    public int sym() {
        int mask = objectSize == ElfFile.CLASS_32 ? 8 : 32;
        return (int) (info >> mask);
    }

    public int type() {
        long mask = objectSize == ElfFile.CLASS_32 ? 0xff : 0xffffffffL;
        return (int) (info & mask);
    }

    public long addend() {
        return addend;
    }

    public boolean isAndroid() {
        return android;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ElfRelocation that = (ElfRelocation) o;
        return offset == that.offset &&
                info == that.info &&
                addend == that.addend;
    }

    @Override
    public int hashCode() {
        return Objects.hash(offset, info, addend);
    }

}
