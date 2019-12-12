package cn.banny.unidbg;

import cn.banny.unidbg.memory.MemRegion;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import unicorn.Unicorn;

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

    public final Number[] callFunction(Emulator emulator, String symbolName, Object... args) {
        Symbol symbol = findSymbolByName(symbolName, false);
        if (symbol == null) {
            throw new IllegalStateException("find symbol failed: " + symbolName);
        }
        if (symbol.isUndef()) {
            throw new IllegalStateException(symbolName + " is NOT defined");
        }

        return symbol.call(emulator, args);
    }

    public final Symbol findSymbolByName(String name) {
        return findSymbolByName(name, true);
    }

    public abstract Symbol findSymbolByName(String name, boolean withDependencies);

    public abstract Symbol findNearestSymbolByAddress(long addr);

    protected final Symbol findDependencySymbolByName(String name) {
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

    private UnicornPointer pathPointer;

    protected abstract String getPath();

    /**
     * 注册符号
     * @param symbolName 符号名称
     * @param address 符号的内存地址
     */
    public abstract void registerSymbol(String symbolName, long address);

    public final UnicornPointer createPathMemory(SvcMemory svcMemory) {
        if (this.pathPointer == null) {
            byte[] path = getPath().getBytes();
            this.pathPointer = svcMemory.allocate(path.length + 1, "Module.path");
            this.pathPointer.write(0, path, 0, path.length);
            this.pathPointer.setByte(path.length, (byte) 0);
        }
        return this.pathPointer;
    }

}
