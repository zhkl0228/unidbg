package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Symbol;

import java.io.IOException;

class IndirectSymbol extends Symbol {

    private final MachOModule module;
    final String symbol;

    IndirectSymbol(String name, MachOModule module, String symbol) {
        super(name);
        this.module = module;
        this.symbol = symbol;
    }

    private Symbol actualSymbol;

    final Symbol resolveSymbol() throws IOException {
        if (actualSymbol != null) {
            return actualSymbol;
        }

        actualSymbol = module.findSymbolByName(symbol, true);
        return actualSymbol;
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long getAddress() {
        return 0;
    }

    @Override
    public long getValue() {
        return 0;
    }

    @Override
    public boolean isUndef() {
        return true;
    }

}
