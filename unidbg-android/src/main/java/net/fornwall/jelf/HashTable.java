package net.fornwall.jelf;

import java.io.IOException;

public interface HashTable {

    /**
     * This method doesn't work every time and is unreliable. Use ELFSection.getELFSymbol(String) to retrieve symbols by
     * name. NOTE: since this method is currently broken it will always return null.
     */
    ElfSymbol getSymbol(ElfSymbolStructure symbolStructure, String symbolName) throws IOException;

    int getNumBuckets();

}
