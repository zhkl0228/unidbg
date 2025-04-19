package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import org.apache.commons.io.FilenameUtils;

class ExternalSymbol extends Symbol {

    private final MachOModule module;
    private final MachOSymbol symbol;

    ExternalSymbol(String name, MachOModule module, MachOSymbol symbol) {
        super(name);
        this.module = module;
        this.symbol = symbol;
    }

    private Symbol actualSymbol;

    final Symbol resolveSymbol() {
        if (actualSymbol != null) {
            return actualSymbol;
        }

        if (!symbol.isExternalSymbol()) {
            throw new UnsupportedOperationException(getName());
        }
        int ordinal = symbol.getLibraryOrdinal();
        if (ordinal <= module.ordinalList.size()) {
            String path = module.ordinalList.get(ordinal - 1);
            MachOModule reexportedFrom = module.loader.modules.get(FilenameUtils.getName(path));
            if (reexportedFrom != null) {
                actualSymbol = reexportedFrom.findSymbolByName(getName(), false);
            }
        } else {
            throw new IllegalStateException("ordinal=" + ordinal);
        }
        if (actualSymbol == null) {
            throw new IllegalStateException("symbol=" + symbol);
        }
        return actualSymbol;
    }

    private Symbol checkSymbol() {
        Symbol symbol = resolveSymbol();
        if (symbol == null) {
            throw new IllegalStateException("symbol is null");
        }
        return symbol;
    }

    @Override
    public Number call(Emulator<?> emulator, Object... args) {
        return checkSymbol().call(emulator, args);
    }

    @Override
    public long getAddress() {
        return checkSymbol().getAddress();
    }

    @Override
    public long getValue() {
        return checkSymbol().getValue();
    }

    @Override
    public boolean isUndef() {
        return checkSymbol().isUndef();
    }

    @Override
    public String getModuleName() {
        return checkSymbol().getModuleName();
    }

}
