package cn.banny.emulator.linux;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.*;
import cn.banny.emulator.linux.android.dvm.Hashable;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.InitFunction;
import com.sun.jna.Pointer;
import net.fornwall.jelf.ElfSymbol;
import net.fornwall.jelf.SymbolLocator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.*;

public class LinuxModule extends Module {

    private static final Log log = LogFactory.getLog(LinuxModule.class);

    private final SymbolLocator dynsym;
    private final List<ModuleSymbol> unresolvedSymbol;
    public final List<InitFunction> initFunctionList;

    public LinuxModule(long base, long size, String name, SymbolLocator dynsym,
                       List<ModuleSymbol> unresolvedSymbol, List<InitFunction> initFunctionList, Map<String, Module> neededLibraries, List<MemRegion> regions) {
        super(name, base, size, neededLibraries, regions);

        this.dynsym = dynsym;
        this.unresolvedSymbol = unresolvedSymbol;
        this.initFunctionList = initFunctionList;
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

    @Override
    public final Symbol findSymbolByName(String name, boolean withDependencies) throws IOException {
        ElfSymbol elfSymbol = dynsym.getELFSymbolByName(name);
        if (elfSymbol != null && !elfSymbol.isUndef()) {
            return new LinuxSymbol(this, elfSymbol);
        }

        if (withDependencies) {
            return findDependencySymbolByName(name);
        }
        return null;
    }

    public ElfSymbol getELFSymbolByName(String name) throws IOException {
        return dynsym.getELFSymbolByName(name);
    }

    @Override
    public Symbol findNearestSymbolByAddress(long addr) {
        throw new UnsupportedOperationException();
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

    @Override
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

    final Map<String, Long> hookMap = new HashMap<>();

    @Override
    public String toString() {
        return "LinuxModule{" +
                "base=0x" + Long.toHexString(base) +
                ", size=" + size +
                ", name='" + name + '\'' +
                '}';
    }
}
