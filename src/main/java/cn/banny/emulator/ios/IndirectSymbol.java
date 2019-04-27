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

    private Symbol checkSymbol() {
        try {
            Symbol symbol = resolveSymbol();
            if (symbol == null) {
                throw new IllegalStateException("symbol is null");
            }
            return symbol;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
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
