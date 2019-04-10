package cn.banny.emulator.linux;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.ByteArrayNumber;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.StringNumber;
import cn.banny.emulator.linux.android.dvm.Hashable;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import net.fornwall.jelf.ElfSymbol;
import net.fornwall.jelf.SymbolLocator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.*;

public class Module {

    private static final Log log = LogFactory.getLog(Module.class);

    public final long base;
    public final long size;
    private final SymbolLocator dynsym;
    public final String name;
    private final List<ModuleSymbol> unresolvedSymbol;
    public final List<InitFunction> initFunctionList;
    private final Map<String, Module> neededLibraries;
    private final List<MemRegion> regions;

    public Module(long base, long size, String name, SymbolLocator dynsym,
                  List<ModuleSymbol> unresolvedSymbol, List<InitFunction> initFunctionList, Map<String, Module> neededLibraries, List<MemRegion> regions) {
        this.base = base;
        this.size = size;
        this.name = name;

        this.dynsym = dynsym;
        this.unresolvedSymbol = unresolvedSymbol;
        this.initFunctionList = initFunctionList;

        this.neededLibraries = neededLibraries;
        this.regions = regions;
    }

    void unload(Unicorn unicorn) {
        for (MemRegion region : regions) {
            unicorn.mem_unmap(region.begin, region.end - region.begin);
        }
    }

    private long entryPoint;

    void setEntryPoint(long entryPoint) {
        this.entryPoint = entryPoint;
    }

    void callInitFunction(Emulator emulator, boolean mustCallInit) throws IOException {
        if (!mustCallInit && !unresolvedSymbol.isEmpty()) {
            for (ModuleSymbol moduleSymbol : unresolvedSymbol) {
                log.info("[" + name + "]" + moduleSymbol.getSymbol().getName() + " symbol is missing before init relocationAddr=" + moduleSymbol.getRelocationAddr());
            }
            return;
        }

        while (!initFunctionList.isEmpty()) {
            InitFunction initFunction = initFunctionList.remove(0);
            initFunction.call(emulator);
        }
    }

    public List<ModuleSymbol> getUnresolvedSymbol() {
        return unresolvedSymbol;
    }

    public List<MemRegion> getRegions() {
        return regions;
    }

    public Symbol findSymbolByName(String name) throws IOException {
        return findSymbolByName(name, true);
    }

    private Symbol findSymbolByName(String name, boolean withDependencies) throws IOException {
        ElfSymbol elfSymbol = dynsym.getELFSymbolByName(name);
        if (elfSymbol != null && !elfSymbol.isUndef()) {
            return new Symbol(this, elfSymbol);
        }

        if (withDependencies) {
            for (Module module : neededLibraries.values()) {
                Symbol symbol = module.findSymbolByName(name, true);
                if (symbol != null) {
                    return symbol;
                }
            }
        }
        return null;
    }

    public ElfSymbol getELFSymbolByName(String name) throws IOException {
        return dynsym.getELFSymbolByName(name);
    }

    public int callEntry(Emulator emulator, Object... args) {
        if (entryPoint <= 0) {
            throw new IllegalStateException("Invalid entry point");
        }

        Memory memory = emulator.getMemory();
        final UnicornPointer stack = memory.allocateStack(0);

        int argc = 0;
        List<Pointer> argv = new ArrayList<>();

        argv.add(memory.writeStackString(emulator.getProcessName()));
        argc++;

        for (int i = 0; args != null && i < args.length; i++) {
            String arg = String.valueOf(args[i]);
            argv.add(memory.writeStackString(arg));
            argc++;
        }

        Pointer auxvPointer = memory.allocateStack(4);
        assert auxvPointer != null;
        auxvPointer.setPointer(0, null);

        Pointer envPointer = memory.allocateStack(4);
        assert envPointer != null;
        envPointer.setPointer(0, null);

        Pointer pointer = memory.allocateStack(4);
        assert pointer != null;
        pointer.setPointer(0, null); // NULL-terminated argv

        Collections.reverse(argv);
        for (Pointer arg : argv) {
            pointer = memory.allocateStack(4);
            assert pointer != null;
            pointer.setPointer(0, arg);
        }

        UnicornPointer kernelArgumentBlock = memory.allocateStack(4);
        assert kernelArgumentBlock != null;
        kernelArgumentBlock.setInt(0, argc);

        if (log.isDebugEnabled()) {
            UnicornPointer sp = memory.allocateStack(0);
            byte[] data = sp.getByteArray(0, (int) (stack.peer - sp.peer));
            Inspector.inspect(data, "kernelArgumentBlock=" + kernelArgumentBlock + ", envPointer=" + envPointer + ", auxvPointer=" + auxvPointer);
        }

        return emulator.eEntry(base + entryPoint, kernelArgumentBlock.peer).intValue();
    }

    public Number[] callFunction(Emulator emulator, String symbolName, Object... args) throws IOException {
        Symbol symbol = findSymbolByName(symbolName, false);
        if (symbol == null) {
            throw new IllegalStateException("find symbol failed: " + symbolName);
        }
        if (symbol.elfSymbol.isUndef()) {
            throw new IllegalStateException(symbolName + " is NOT defined");
        }

        return symbol.call(emulator, args);
    }

    public Number[] callFunction(Emulator emulator, long offset, Object... args) {
        return emulateFunction(emulator, base + offset, args);
    }

    public static Number[] emulateFunction(Emulator emulator, long address, Object... args) {
        List<Number> list = new ArrayList<>(args.length);
        for (Object arg : args) {
            if (arg instanceof String) {
                list.add(new StringNumber((String) arg));
            } else if(arg instanceof byte[]) {
                list.add(new ByteArrayNumber((byte[]) arg));
            } else if(arg instanceof UnicornPointer) {
                UnicornPointer pointer = (UnicornPointer) arg;
                list.add(pointer.peer);
            } else if (arg instanceof Number) {
                list.add((Number) arg);
            } else if(arg instanceof Hashable) {
                list.add(arg.hashCode()); // dvm object
            } else if(arg == null) {
                list.add(0); // null
            } else {
                throw new IllegalStateException("Unsupported arg: " + arg);
            }
        }
        return emulator.eFunc(address, list.toArray(new Number[0]));
    }

    Collection<Module> getNeededLibraries() {
        return neededLibraries.values();
    }

    public Module getDependencyModule(String name) {
        return neededLibraries.get(name);
    }

    private int referenceCount;

    void addReferenceCount() {
        referenceCount++;
    }

    int decrementReferenceCount() {
        return --referenceCount;
    }

    final Map<String, Long> hookMap = new HashMap<>();

    @Override
    public String toString() {
        return "Module{" +
                "base=0x" + Long.toHexString(base) +
                ", size=" + size +
                ", name='" + name + '\'' +
                '}';
    }

    boolean forceCallInit;

    public void setForceCallInit() {
        this.forceCallInit = true;
    }
}
