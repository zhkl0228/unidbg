package com.github.unidbg;

import com.github.unidbg.linux.android.dvm.Hashable;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.pointer.UnicornStructure;
import unicorn.Unicorn;

import java.util.ArrayList;
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

    public abstract Number[] callFunction(Emulator<?> emulator, long offset, Object... args);

    public final Number[] callFunction(Emulator<?> emulator, String symbolName, Object... args) {
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

    @SuppressWarnings("unused")
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

    public  abstract int callEntry(Emulator<?> emulator, String... args);

    private UnicornPointer pathPointer;

    public abstract String getPath();

    /**
     * 注册符号
     * @param symbolName 符号名称
     * @param address 符号的内存地址
     */
    public abstract void registerSymbol(String symbolName, long address);

    public final UnicornPointer createPathMemory(SvcMemory svcMemory) {
        if (this.pathPointer == null) {
            byte[] path = getPath().getBytes();
            this.pathPointer = svcMemory.allocate(path.length + 1, "Module.path: " + getPath());
            this.pathPointer.write(0, path, 0, path.length);
            this.pathPointer.setByte(path.length, (byte) 0);
        }
        return this.pathPointer;
    }

    public static Number[] emulateFunction(Emulator<?> emulator, long address, Object... args) {
        List<Number> list = new ArrayList<>(args.length);
        for (Object arg : args) {
            if (arg instanceof String) {
                list.add(new StringNumber((String) arg));
            } else if(arg instanceof byte[]) {
                list.add(new ByteArrayNumber((byte[]) arg));
            } else if(arg instanceof UnicornPointer) {
                UnicornPointer pointer = (UnicornPointer) arg;
                list.add(new PointerNumber(pointer));
            } else if(arg instanceof UnicornStructure) {
                UnicornStructure structure = (UnicornStructure) arg;
                list.add(new PointerNumber((UnicornPointer) structure.getPointer()));
            } else if (arg instanceof Number) {
                list.add((Number) arg);
            } else if(arg instanceof Hashable) {
                list.add(arg.hashCode()); // dvm object
            } else if(arg == null) {
                list.add(new PointerNumber(null)); // null
            } else {
                throw new IllegalStateException("Unsupported arg: " + arg);
            }
        }
        return emulator.eFunc(address, list.toArray(new Number[0]));
    }

    public boolean isVirtual() {
        return false;
    }

}
