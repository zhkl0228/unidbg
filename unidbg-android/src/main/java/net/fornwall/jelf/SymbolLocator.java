package net.fornwall.jelf;

import java.io.IOException;

public interface SymbolLocator {

    ElfSymbol getELFSymbol(int index) throws IOException;

    ElfSymbol getELFSymbolByName(String name) throws IOException;

    ElfSymbol getELFSymbolByAddr(long addr) throws IOException;

}
