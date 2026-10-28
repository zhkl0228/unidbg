package com.github.unidbg.linux;

import net.fornwall.jelf.ElfSymbol;
import net.fornwall.jelf.SymbolLocator;

/**
 * 空符号定位器，用于加壳 SO 无法解析符号表的情况。
 */
public class EmptySymbolLocator implements SymbolLocator {

    @Override
    public ElfSymbol getELFSymbol(int index) {
        return null;
    }

    @Override
    public ElfSymbol getELFSymbolByName(String name) {
        return null;
    }

    @Override
    public ElfSymbol getELFSymbolByAddr(long addr) {
        return null;
    }
}
