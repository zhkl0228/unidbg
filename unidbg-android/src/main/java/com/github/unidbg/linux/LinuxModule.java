package com.github.unidbg.linux;

import com.github.unidbg.Alignment;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.VirtualSymbol;
import com.sun.jna.Pointer;
import net.fornwall.jelf.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.*;

public class LinuxModule extends Module {

    private static final Log log = LogFactory.getLog(LinuxModule.class);

    static LinuxModule createVirtualModule(String name, final Map<String, UnidbgPointer> symbols, Emulator<?> emulator) {
        if (symbols.isEmpty()) {
            throw new IllegalArgumentException("symbols is empty");
        }

        List<UnidbgPointer> list = new ArrayList<>(symbols.values());
        Collections.sort(list, new Comparator<UnidbgPointer>() {
            @Override
            public int compare(UnidbgPointer o1, UnidbgPointer o2) {
                return (int) (o1.peer - o2.peer);
            }
        });
        UnidbgPointer first = list.get(0);
        UnidbgPointer last = list.get(list.size() - 1);
        Alignment alignment = ARM.align(first.peer, last.peer - first.peer, emulator.getPageAlign());
        final long base = alignment.address;
        final long size = alignment.size;

        if (log.isDebugEnabled()) {
            log.debug("createVirtualModule first=0x" + Long.toHexString(first.peer) + ", last=0x" + Long.toHexString(last.peer) + ", base=0x" + Long.toHexString(base) + ", size=0x" + Long.toHexString(size));
        }

        LinuxModule module = new LinuxModule(base, size, name, null,
                Collections.<ModuleSymbol>emptyList(), Collections.<InitFunction>emptyList(),
                Collections.<String, Module>emptyMap(), Collections.<MemRegion>emptyList(), null, null) {
            @Override
            public Symbol findSymbolByName(String name, boolean withDependencies) {
                UnidbgPointer pointer = symbols.get(name);
                if (pointer != null) {
                    return new VirtualSymbol(name, this, pointer.peer);
                } else {
                    return null;
                }
            }
            @Override
            public ElfSymbol getELFSymbolByName(String name) {
                return null;
            }
            @Override
            public boolean isVirtual() {
                return true;
            }
        };
        for (Map.Entry<String, UnidbgPointer> entry : symbols.entrySet()) {
            module.registerSymbol(entry.getKey(), entry.getValue().peer);
        }
        return module;
    }

    private final SymbolLocator dynsym;
    private final List<ModuleSymbol> unresolvedSymbol;
    public final List<InitFunction> initFunctionList;
    public final MemoizedObject<ArmExIdx> armExIdx;
    public final MemoizedObject<GnuEhFrameHeader> ehFrameHeader;

    LinuxModule(long base, long size, String name, SymbolLocator dynsym,
                List<ModuleSymbol> unresolvedSymbol, List<InitFunction> initFunctionList, Map<String, Module> neededLibraries, List<MemRegion> regions,
                MemoizedObject<ArmExIdx> armExIdx, MemoizedObject<GnuEhFrameHeader> ehFrameHeader) {
        super(name, base, size, neededLibraries, regions);

        this.dynsym = dynsym;
        this.unresolvedSymbol = unresolvedSymbol;
        this.initFunctionList = initFunctionList;
        this.armExIdx = armExIdx;
        this.ehFrameHeader = ehFrameHeader;
    }

    void callInitFunction(Emulator<?> emulator, boolean mustCallInit) throws IOException {
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
    public Symbol findSymbolByName(String name, boolean withDependencies) {
        try {
            ElfSymbol elfSymbol = dynsym.getELFSymbolByName(name);
            if (elfSymbol != null && !elfSymbol.isUndef()) {
                return new LinuxSymbol(this, elfSymbol);
            }

            if (withDependencies) {
                return findDependencySymbolByName(name);
            }
            return null;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public ElfSymbol getELFSymbolByName(String name) throws IOException {
        return dynsym.getELFSymbolByName(name);
    }

    @Override
    public Symbol findNearestSymbolByAddress(long addr) {
        try {
            ElfSymbol elfSymbol = dynsym.getELFSymbolByAddr(addr - base);
            if (elfSymbol != null && !elfSymbol.isUndef()) {
                return new LinuxSymbol(this, elfSymbol);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int callEntry(Emulator<?> emulator, String... args) {
        if (entryPoint <= 0) {
            throw new IllegalStateException("Invalid entry point");
        }

        Memory memory = emulator.getMemory();
        final UnidbgPointer stack = memory.allocateStack(0);

        int argc = 0;
        List<Pointer> argv = new ArrayList<>();

        argv.add(memory.writeStackString(emulator.getProcessName()));
        argc++;

        for (int i = 0; args != null && i < args.length; i++) {
            String arg = args[i];
            argv.add(memory.writeStackString(arg));
            argc++;
        }

        if (argc % 2 != 0) { // alignment sp
            memory.allocateStack(emulator.getPointerSize());
        }

        Pointer auxvPointer = memory.allocateStack(emulator.getPointerSize());
        assert auxvPointer != null;
        auxvPointer.setPointer(0, null);

        Pointer envPointer = memory.allocateStack(emulator.getPointerSize());
        assert envPointer != null;
        envPointer.setPointer(0, null);

        Pointer pointer = memory.allocateStack(emulator.getPointerSize());
        assert pointer != null;
        pointer.setPointer(0, null); // NULL-terminated argv

        Collections.reverse(argv);
        for (Pointer arg : argv) {
            pointer = memory.allocateStack(emulator.getPointerSize());
            assert pointer != null;
            pointer.setPointer(0, arg);
        }

        UnidbgPointer kernelArgumentBlock = memory.allocateStack(emulator.getPointerSize());
        assert kernelArgumentBlock != null;
        kernelArgumentBlock.setInt(0, argc);

        if (log.isDebugEnabled()) {
            UnidbgPointer sp = memory.allocateStack(0);
            byte[] data = sp.getByteArray(0, (int) (stack.peer - sp.peer));
            Inspector.inspect(data, "kernelArgumentBlock=" + kernelArgumentBlock + ", envPointer=" + envPointer + ", auxvPointer=" + auxvPointer);
        }

        return emulator.eEntry(base + entryPoint, kernelArgumentBlock.peer).intValue();
    }

    @Override
    public Number[] callFunction(Emulator<?> emulator, long offset, Object... args) {
        return emulateFunction(emulator, base + offset, args);
    }

    @Override
    public String getPath() {
        return name;
    }

    final Map<String, Long> hookMap = new HashMap<>();

    @Override
    public void registerSymbol(String symbolName, long address) {
        hookMap.put(symbolName, address);
    }

    @Override
    public String toString() {
        return "LinuxModule{" +
                "base=0x" + Long.toHexString(base) +
                ", size=" + size +
                ", name='" + name + '\'' +
                '}';
    }
}
