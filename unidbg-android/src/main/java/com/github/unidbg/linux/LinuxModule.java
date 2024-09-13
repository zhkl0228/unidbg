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
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.VirtualSymbol;
import com.sun.jna.Pointer;
import net.fornwall.jelf.ArmExIdx;
import net.fornwall.jelf.ElfDynamicStructure;
import net.fornwall.jelf.ElfException;
import net.fornwall.jelf.ElfFile;
import net.fornwall.jelf.ElfSection;
import net.fornwall.jelf.ElfSymbol;
import net.fornwall.jelf.GnuEhFrameHeader;
import net.fornwall.jelf.MemoizedObject;
import net.fornwall.jelf.SymbolLocator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LinuxModule extends Module {

    private static final Logger log = LoggerFactory.getLogger(LinuxModule.class);

    static LinuxModule createVirtualModule(String name, final Map<String, UnidbgPointer> symbols, Emulator<?> emulator) {
        if (symbols.isEmpty()) {
            throw new IllegalArgumentException("symbols is empty");
        }

        List<UnidbgPointer> list = new ArrayList<>(symbols.values());
        list.sort((o1, o2) -> (int) (o1.peer - o2.peer));
        UnidbgPointer first = list.get(0);
        UnidbgPointer last = list.get(list.size() - 1);
        Alignment alignment = ARM.align(first.peer, last.peer - first.peer, emulator.getPageAlign());
        final long base = alignment.address;
        final long size = alignment.size;

        if (log.isDebugEnabled()) {
            log.debug("createVirtualModule first=0x{}, last=0x{}, base=0x{}, size=0x{}", Long.toHexString(first.peer), Long.toHexString(last.peer), Long.toHexString(base), Long.toHexString(size));
        }

        LinuxModule module = new LinuxModule(base, base, size, name, null,
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyMap(), Collections.emptyList(),
                null, null, null, null, null, null) {
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
    private final ElfSection symbolTableSection;
    public final ElfFile elfFile;
    public final ElfDynamicStructure dynamicStructure;
    public final long virtualBase;

    LinuxModule(long virtualBase, long base, long size, String name, SymbolLocator dynsym,
                List<ModuleSymbol> unresolvedSymbol, List<InitFunction> initFunctionList, Map<String, Module> neededLibraries, List<MemRegion> regions,
                MemoizedObject<ArmExIdx> armExIdx, MemoizedObject<GnuEhFrameHeader> ehFrameHeader,
                ElfSection symbolTableSection, ElfFile elfFile, ElfDynamicStructure dynamicStructure, LibraryFile libraryFile) {
        super(name, base, size, neededLibraries, regions, libraryFile);

        this.virtualBase = virtualBase;
        this.dynsym = dynsym;
        this.unresolvedSymbol = unresolvedSymbol;
        this.initFunctionList = initFunctionList;
        this.armExIdx = armExIdx;
        this.ehFrameHeader = ehFrameHeader;
        this.symbolTableSection = symbolTableSection;
        this.elfFile = elfFile;
        this.dynamicStructure = dynamicStructure;
    }

    @Override
    public int virtualMemoryAddressToFileOffset(long offset) {
        try {
            return (int) elfFile.virtualMemoryAddrToFileOffset(offset);
        } catch (ElfException e) {
            return -1;
        } catch (IOException e) {
            throw new IllegalStateException("virtualMemoryAddressToFileOffset offset=0x" + Long.toHexString(offset));
        }
    }

    void callInitFunction(Emulator<?> emulator, boolean mustCallInit) throws IOException {
        if (!mustCallInit && !unresolvedSymbol.isEmpty()) {
            for (ModuleSymbol moduleSymbol : unresolvedSymbol) {
                log.info("[{}]{} symbol is missing before init relocationAddr={}", name, moduleSymbol.getSymbol().getName(), moduleSymbol.getRelocationAddr());
            }
            return;
        }

        int index = 0;
        while (!initFunctionList.isEmpty()) {
            InitFunction initFunction = initFunctionList.remove(0);
            long initAddress = initFunction.getAddress();
            if (initFunctionListener != null) {
                initFunctionListener.onPreCallInitFunction(this, initAddress, index);
            }
            initAddress = initFunction.call(emulator);
            if (initFunctionListener != null) {
                initFunctionListener.onPostCallInitFunction(this, initAddress, index);
            }
            index++;
        }
    }

    public List<ModuleSymbol> getUnresolvedSymbol() {
        return unresolvedSymbol;
    }

    final Map<String, ModuleSymbol> resolvedSymbols = new HashMap<>();

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
    public Symbol findClosestSymbolByAddress(long address, boolean fast) {
        try {
            long soaddr = address - base;
            if (soaddr <= 0) {
                return null;
            }
            ElfSymbol elfSymbol = dynsym == null ? null : dynsym.getELFSymbolByAddr(soaddr);
            if (symbolTableSection != null && elfSymbol == null) {
                elfSymbol = symbolTableSection.getELFSymbolByAddr(soaddr);
            }
            Symbol symbol = null;
            if (elfSymbol != null) {
                symbol = new LinuxSymbol(this, elfSymbol);
            }
            long entry = base + entryPoint;
            if (address >= entry && (symbol == null || entry > symbol.getAddress())) {
                symbol = new VirtualSymbol("start", this, entry);
            }
            return symbol;
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
    public Number callFunction(Emulator<?> emulator, long offset, Object... args) {
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
