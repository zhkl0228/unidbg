package cn.banny.emulator;

import cn.banny.emulator.memory.MemRegion;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public abstract class Module {

    public final String name;
    public final long base;
    public final long size;
    protected final Map<String, Module> neededLibraries;
    private final List<MemRegion> regions;

    public Module(String name, long base, long size, Map<String, Module> neededLibraries, List<MemRegion> regions) {
        this.name = name;
        this.base = base;
        this.size = size;

        this.neededLibraries = neededLibraries;
        this.regions = regions;
    }

    public final List<MemRegion> getRegions() {
        return regions;
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

    public abstract Symbol findSymbolByName(String name, boolean withDependencies) throws IOException;

    public abstract Symbol findNearestSymbolByAddress(long addr);

    protected final Symbol findDependencySymbolByName(String name) throws IOException {
        for (Module module : neededLibraries.values()) {
            Symbol symbol = module.findSymbolByName(name, true);
            if (symbol != null) {
                return symbol;
            }
        }
        return null;
    }

    private int referenceCount;

    public void addReferenceCount() {
        referenceCount++;
    }

    public int decrementReferenceCount() {
        return --referenceCount;
    }

    private boolean forceCallInit;

    public boolean isForceCallInit() {
        return forceCallInit;
    }

    public void setForceCallInit() {
        this.forceCallInit = true;
    }

    public final void unload(Unicorn unicorn) {
        for (MemRegion region : regions) {
            unicorn.mem_unmap(region.begin, region.end - region.begin);
        }
    }

    public Collection<Module> getNeededLibraries() {
        return neededLibraries.values();
    }

    public Module getDependencyModule(String name) {
        return neededLibraries.get(name);
    }

    protected long entryPoint;

    public void setEntryPoint(long entryPoint) {
        this.entryPoint = entryPoint;
    }

    public  abstract int callEntry(Emulator emulator, Object... args);

}
