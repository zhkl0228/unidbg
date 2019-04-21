package cn.banny.emulator;

import cn.banny.emulator.memory.MemRegion;

import java.io.IOException;
import java.util.List;

public abstract class Module {

    public final String name;
    public final long base;
    public final long size;

    public Module(String name, long base, long size) {
        this.name = name;
        this.base = base;
        this.size = size;
    }

    public abstract Number[] callFunction(Emulator emulator, long offset, Object... args);

    public final Number[] callFunction(Emulator emulator, String symbolName, Object... args) throws IOException {
        Symbol symbol = findSymbolByName(symbolName, false);
        if (symbol == null) {
            throw new IllegalStateException("find symbol failed: " + symbolName);
        }
        if (symbol.isUndef()) {
            throw new IllegalStateException(symbolName + " is NOT defined");
        }

        return symbol.call(emulator, args);
    }

    public final Symbol findSymbolByName(String name) throws IOException {
        return findSymbolByName(name, true);
    }

    protected abstract Symbol findSymbolByName(String name, boolean withDependencies) throws IOException;

    private int referenceCount;

    public void addReferenceCount() {
        referenceCount++;
    }

    public int decrementReferenceCount() {
        return --referenceCount;
    }

    public abstract List<MemRegion> getRegions();

    private boolean forceCallInit;

    public boolean isForceCallInit() {
        return forceCallInit;
    }

    public void setForceCallInit() {
        this.forceCallInit = true;
    }

}
