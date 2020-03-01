package com.github.unidbg.ios;

import com.github.unidbg.Alignment;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.virtualmodule.VirtualSymbol;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class MachOModule extends Module implements com.github.unidbg.ios.MachO {

    final MachO machO;
    private final MachO.SymtabCommand symtabCommand;
    final MachO.DysymtabCommand dysymtabCommand;
    final ByteBuffer buffer;
    final List<NeedLibrary> lazyLoadNeededList;
    final Map<String, Module> upwardLibraries;
    private final Map<String, Module> exportModules;
    private final String path;
    final MachO.DyldInfoCommand dyldInfoCommand;

    final List<InitFunction> routines;
    final List<InitFunction> initFunctionList;

    public final long machHeader;

    boolean indirectSymbolBound;
    boolean lazyPointerProcessed;

    private final Map<String, Symbol> symbolMap = new HashMap<>();

    private final Log log;

    final boolean executable;
    private final MachOLoader loader;

    MachOModule(MachO machO, String name, long base, long size, Map<String, Module> neededLibraries, List<MemRegion> regions,
                MachO.SymtabCommand symtabCommand, MachO.DysymtabCommand dysymtabCommand, ByteBuffer buffer,
                List<NeedLibrary> lazyLoadNeededList, Map<String, Module> upwardLibraries, Map<String, Module> exportModules,
                String path, Emulator<?> emulator, MachO.DyldInfoCommand dyldInfoCommand, UnicornPointer envp, UnicornPointer apple, UnicornPointer vars,
                long machHeader, boolean executable, MachOLoader loader) {
        super(name, base, size, neededLibraries, regions);
        this.machO = machO;
        this.symtabCommand = symtabCommand;
        this.dysymtabCommand = dysymtabCommand;
        this.buffer = buffer;
        this.lazyLoadNeededList = lazyLoadNeededList;
        this.upwardLibraries = upwardLibraries;
        this.exportModules = exportModules;
        this.path = path;
        this.dyldInfoCommand = dyldInfoCommand;
        this.envp = envp;
        this.apple = apple;
        this.vars = vars;
        this.machHeader = machHeader;
        this.executable = executable;
        this.loader = loader;

        this.log = LogFactory.getLog("com.github.unidbg.ios." + name);
        this.routines = machO == null ? Collections.<InitFunction>emptyList() : parseRoutines(machO);
        this.initFunctionList = machO == null ? Collections.<InitFunction>emptyList() : parseInitFunction(machO, buffer.duplicate(), name, emulator);

        if (machO == null) {
            return;
        }

        final Map<String, ExportSymbol> exportSymbols = processExportNode(log, dyldInfoCommand, buffer);

        if (symtabCommand != null) {
            buffer.limit((int) (symtabCommand.strOff() + symtabCommand.strSize()));
            buffer.position((int) symtabCommand.strOff());
            ByteBuffer strBuffer = buffer.slice();
            ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(strBuffer);
            for (MachO.SymtabCommand.Nlist nlist : symtabCommand.symbols()) {
                int type = nlist.type() & N_TYPE;
                if (nlist.un() == 0) {
                    continue;
                }

                boolean isWeakDef = (nlist.desc() & N_WEAK_DEF) != 0;
                boolean isThumb = (nlist.desc() & N_ARM_THUMB_DEF) != 0;
                strBuffer.position((int) nlist.un());
                String symbolName = new String(io.readBytesTerm(0, false, true, true), StandardCharsets.US_ASCII);
                if ((type == N_SECT || type == N_ABS) && (nlist.type() & N_STAB) == 0) {
                    ExportSymbol exportSymbol = null;
                    if (exportSymbols.isEmpty() || (exportSymbol = exportSymbols.get(symbolName)) != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("nlist un=0x" + Long.toHexString(nlist.un()) + ", symbolName=" + symbolName + ", type=0x" + Long.toHexString(nlist.type()) + ", isWeakDef=" + isWeakDef + ", isThumb=" + isThumb + ", value=0x" + Long.toHexString(nlist.value()));
                        }

                        MachOSymbol symbol = new MachOSymbol(this, nlist, symbolName);
                        if (exportSymbol != null && symbol.getAddress() == exportSymbol.other) {
                            if (log.isDebugEnabled()) {
                                log.debug("nlist un=0x" + Long.toHexString(nlist.un()) + ", symbolName=" + symbolName + ", value=0x" + Long.toHexString(nlist.value()) + ", address=0x" + Long.toHexString(exportSymbol.getValue()) + ", other=0x" + Long.toHexString(exportSymbol.other));
                            }
                            symbolMap.put(symbolName, exportSymbol);
                        } else {
                            symbolMap.put(symbolName, symbol);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("nlist FILTER un=0x" + Long.toHexString(nlist.un()) + ", symbolName=" + symbolName + ", type=0x" + Long.toHexString(nlist.type()) + ", isWeakDef=" + isWeakDef + ", isThumb=" + isThumb + ", value=0x" + Long.toHexString(nlist.value()));
                        }
                    }
                } else if (type == N_INDR) {
                    strBuffer.position(nlist.value().intValue());
                    String indirectSymbol = new String(io.readBytesTerm(0, false, true, true), StandardCharsets.US_ASCII);
                    if (!symbolName.equals(indirectSymbol)) {
                        if (log.isDebugEnabled()) {
                            log.debug("nlist indirect symbolName=" + symbolName + ", indirectSymbol=" + indirectSymbol);
                        }
                        symbolMap.put(symbolName, new IndirectSymbol(symbolName, this, indirectSymbol));
                    }
                }
            }
        }
    }

    @Override
    public int callEntry(Emulator<?> emulator, String... args) {
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
            String arg = args[i];
            argv.add(memory.writeStackString(arg));
            argc++;
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

        if (log.isDebugEnabled()) {
            UnicornPointer sp = memory.allocateStack(0);
            byte[] data = sp.getByteArray(0, (int) (stack.peer - sp.peer));
            Inspector.inspect(data, "callEntry sp=0x" + Long.toHexString(memory.getStackPoint()) + ", envPointer=" + envPointer + ", auxvPointer=" + auxvPointer);
        }

        Pointer argvPointer = memory.allocateStack(0);
        return emulateFunction(emulator, machHeader + entryPoint, argc, argvPointer, envPointer, auxvPointer)[0].intValue();
//        return emulator.eFunc(machHeader + entryPoint, argc, argvPointer)[0].intValue();
    }

    final void doInitialization(Emulator<?> emulator) {
        if (loader.executableModule == null) {
            vars.setPointer(0, UnicornPointer.pointer(emulator, machHeader)); // _NSGetMachExecuteHeader
        }

        callRoutines(emulator);
        for (Module module : neededLibraries.values()) {
            MachOModule mm = (MachOModule) module;
            mm.doInitialization(emulator);
        }
        callInitFunction(emulator);
    }

    final void callRoutines(Emulator<?> emulator) {
        Log log = LogFactory.getLog(MachOModule.class);
        if (log.isDebugEnabled() && !routines.isEmpty()) {
            log.debug("callRoutines name=" + name);
        }
        while (!routines.isEmpty()) {
            InitFunction routine = routines.remove(0);
            routine.call(emulator);
        }
    }

    final void callInitFunction(Emulator<?> emulator) {
        /*if (!initFunctionList.isEmpty() && "libSystem.B.dylib".equals(name)) {
            Module libsystem_c = loader.findModule("libsystem_c.dylib");
            if (libsystem_c != null) {
                long _program_vars_init;
                if (emulator.is64Bit()) {
                    _program_vars_init = 0x9974;
                } else {
                    _program_vars_init = 0x6d10 | 1; // thumb
                }
                libsystem_c.callFunction(emulator, _program_vars_init, vars);

                MachOModule mCoreFoundation = (MachOModule) loader.findModule("CoreFoundation");
                if (mCoreFoundation != null) {
                    mCoreFoundation.callRoutines(emulator);
                }
            }
        }*/

        Log log = LogFactory.getLog(MachOModule.class);
        if (log.isDebugEnabled() && !initFunctionList.isEmpty()) {
            log.debug("callInitFunction name=" + name);
        }

        while (!initFunctionList.isEmpty()) {
            InitFunction initFunction = initFunctionList.remove(0);
            initFunction.call(emulator);
        }
    }

    private void processExportNode(Log log, ByteBuffer buffer, byte[] cummulativeString, int curStrOffset, Map<String, ExportSymbol> map) {
        int terminalSize = Utils.readULEB128(buffer).intValue();

        if (terminalSize != 0) {
            buffer.mark();
            int flags = Utils.readULEB128(buffer).intValue();
            long address;
            long other;
            String importName;
            if ((flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0) {
                address = 0;
                other = Utils.readULEB128(buffer).longValue();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte b;
                while ((b = buffer.get()) != 0) {
                    baos.write(b);
                }
                importName = baos.toString();
            } else {
                address = Utils.readULEB128(buffer).longValue();
                if((flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0) {
                    other = Utils.readULEB128(buffer).longValue();
                } else {
                    other = 0;
                }
                importName = null;
            }
            String symbolName = new String(cummulativeString, 0, curStrOffset);
            map.put(symbolName, new ExportSymbol(symbolName, address, this, base + other, (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE));
            if (log.isDebugEnabled()) {
                log.debug("exportNode symbolName=" + symbolName + ", address=0x" + Long.toHexString(address) + ", other=0x" + Long.toHexString(other) + ", importName=" + importName + ", flags=0x" + Integer.toHexString(flags));
            }
            buffer.reset();
            buffer.position(buffer.position() + terminalSize);
        }

        int childrenCount = buffer.get() & 0xff;
        for (int i = 0; i < childrenCount; i++) {
            int edgeStrLen = 0;
            byte b;
            while ((b = buffer.get()) != 0) {
                cummulativeString[curStrOffset+edgeStrLen] = b;
                ++edgeStrLen;
            }
            cummulativeString[curStrOffset+edgeStrLen] = 0;

            int childNodeOffset = Utils.readULEB128(buffer).intValue();

            ByteBuffer duplicate = buffer.duplicate();
            duplicate.position(childNodeOffset);
            processExportNode(log, duplicate, cummulativeString, curStrOffset+edgeStrLen, map);
        }
    }

    private Map<String, ExportSymbol> processExportNode(Log log, MachO.DyldInfoCommand dyldInfoCommand, ByteBuffer buffer) {
        if (dyldInfoCommand == null) {
            return Collections.emptyMap();
        }

        Map<String, ExportSymbol> map = new HashMap<>();
        if (dyldInfoCommand.exportSize() > 0) {
            buffer = buffer.duplicate();
            buffer.limit((int) (dyldInfoCommand.exportOff() + dyldInfoCommand.exportSize()));
            buffer.position((int) dyldInfoCommand.exportOff());
            processExportNode(log, buffer.slice(), new byte[4000], 0, map);
        }
        return map;
    }

    private List<InitFunction> parseRoutines(MachO machO) {
        List<InitFunction> routines = new ArrayList<>();
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case ROUTINES: {
                    MachO.RoutinesCommand routinesCommand = (MachO.RoutinesCommand) command.body();
                    long address = routinesCommand.initAddress();
                    if (log.isDebugEnabled()) {
                        log.debug("parseRoutines address=0x" + Long.toHexString(address));
                    }
                    routines.add(new MachOModuleInit(this, envp, apple, vars, false, address));
                    break;
                }
                case ROUTINES_64: {
                    MachO.RoutinesCommand64 routinesCommand64 = (MachO.RoutinesCommand64) command.body();
                    long address = routinesCommand64.initAddress();
                    if (log.isDebugEnabled()) {
                        log.debug("parseRoutines64 address=0x" + Long.toHexString(address));
                    }
                    routines.add(new MachOModuleInit(this, envp, apple, vars, false, address));
                    break;
                }
            }
        }
        return routines;
    }

    private List<InitFunction> parseInitFunction(MachO machO, ByteBuffer buffer, String libName, Emulator<?> emulator) {
        List<InitFunction> initFunctionList = new ArrayList<>();
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                        long type = section.flags() & SECTION_TYPE;
                        if (type != S_MOD_INIT_FUNC_POINTERS) {
                            continue;
                        }

                        long elementCount = section.size() / emulator.getPointerSize();
                        buffer.order(ByteOrder.LITTLE_ENDIAN);
                        buffer.limit((int) (section.offset() + section.size()));
                        buffer.position((int) section.offset());
                        for (int i = 0; i < elementCount; i++) {
                            long address = emulator.is32Bit() ? buffer.getInt() : buffer.getLong();
                            if (log.isDebugEnabled()) {
                                log.debug("parseInitFunction libName=" + libName + ", address=0x" + Long.toHexString(address) + ", offset=0x" + Long.toHexString(section.offset()) + ", elementCount=" + elementCount);
                            }
                            initFunctionList.add(new MachOModuleInit(this, envp, apple, vars, true, address));
                        }
                    }
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    for (MachO.SegmentCommand64.Section64 section : segmentCommand64.sections()) {
                        long type = section.flags() & SECTION_TYPE;
                        if (type != S_MOD_INIT_FUNC_POINTERS) {
                            continue;
                        }

                        long elementCount = section.size() / emulator.getPointerSize();
                        buffer.order(ByteOrder.LITTLE_ENDIAN);
                        buffer.limit((int) (section.offset() + section.size()));
                        buffer.position((int) section.offset());
                        for (int i = 0; i < elementCount; i++) {
                            long address = emulator.is32Bit() ? buffer.getInt() : buffer.getLong();
                            if (log.isDebugEnabled()) {
                                log.debug("parseInitFunction libName=" + libName + ", address=0x" + Long.toHexString(address) + ", offset=0x" + Long.toHexString(section.offset()) + ", elementCount=" + elementCount);
                            }
                            initFunctionList.add(new MachOModuleInit(this, envp, apple, vars, true, address));
                        }
                    }
            }
        }
        return initFunctionList;
    }

    private final UnicornPointer envp;
    private final UnicornPointer apple;
    private final UnicornPointer vars;

    final Map<String, Module> neededLibraries() {
        return neededLibraries;
    }

    @Override
    public Number[] callFunction(Emulator<?> emulator, long offset, Object... args) {
        return emulateFunction(emulator, base + offset, args);
    }

    MachOSymbol getSymbolByIndex(int index) {
        buffer.limit((int) (symtabCommand.strOff() + symtabCommand.strSize()));
        buffer.position((int) symtabCommand.strOff());
        ByteBuffer strBuffer = buffer.slice();
        ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(strBuffer);

        MachO.SymtabCommand.Nlist nlist = symtabCommand.symbols().get(index);
        strBuffer.position((int) nlist.un());
        String symbolName = new String(io.readBytesTerm(0, false, true, true), StandardCharsets.US_ASCII);
        return new MachOSymbol(this, nlist, symbolName);
    }

    private final Set<String> failedSymbols = new HashSet<>();

    @Override
    public Symbol findSymbolByName(String name, boolean withDependencies) {
        if (withDependencies && failedSymbols.contains(name)) {
            return null;
        }
        Symbol symbol = findSymbolByNameInternal(name, withDependencies);
        if (withDependencies && symbol == null) {
            failedSymbols.add(name);
        }

        if (symbol != null) {
            if (symbol instanceof IndirectSymbol) {
                IndirectSymbol indirectSymbol = (IndirectSymbol) symbol;
                symbol = indirectSymbol.resolveSymbol();
                if (symbol == null) {
                    log.warn("Resolve indirect symbol failed: name=" + this.name + ", symbolName=" + name + ", indirectSymbol=" + indirectSymbol.symbol + ", neededLibraries=" + neededLibraries.values());
                }
            }
            return symbol;
        } else {
            return null;
        }
    }

    private Symbol findSymbolByNameInternal(String name, boolean withDependencies) {
        Symbol symbol = symbolMap.get(name);
        if (symbol != null) {
            return symbol;
        }

        if (withDependencies) {
            Set<Module> findSet = new LinkedHashSet<>(loader.getLoadedModules().size());
            findSet.addAll(exportModules.values());
            findSet.addAll(upwardLibraries.values());
            findSet.addAll(neededLibraries.values());
            findSet.addAll(loader.getLoadedModules());
            for (Module module : findSet) {
                symbol = module.findSymbolByName(name, false);
                if (symbol != null) {
                    return symbol;
                }
            }
        }

        return null;
    }

    @Override
    public Symbol findNearestSymbolByAddress(long addr) {
        long abs = Long.MAX_VALUE;
        Symbol nearestSymbol = null;
        for (Symbol symbol : symbolMap.values()) {
            if (symbol.getAddress() <= addr) {
                long off = addr - symbol.getAddress();
                if (off < abs) {
                    abs = off;
                    nearestSymbol = symbol;
                }
            }
        }
        return nearestSymbol;
    }

    @Override
    public String toString() {
        return path;
    }

    boolean hasUnresolvedSymbol() {
        return !allSymbolBond || !allLazySymbolBond;
    }

    boolean allSymbolBond;
    boolean allLazySymbolBond;

    final Set<UnicornPointer> addImageCallSet = new HashSet<>();
    final Set<UnicornPointer> boundCallSet = new HashSet<>();
    final Set<UnicornPointer> dependentsInitializedCallSet = new HashSet<>();
    final Set<UnicornPointer> initializedCallSet = new HashSet<>();

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public void registerSymbol(String symbolName, long address) {
        throw new UnsupportedOperationException();
    }

    static MachOModule createVirtualModule(String name, final Map<String, UnicornPointer> symbols, Emulator<?> emulator) {
        if (symbols.isEmpty()) {
            throw new IllegalArgumentException("symbols is empty");
        }

        List<UnicornPointer> list = new ArrayList<>(symbols.values());
        Collections.sort(list, new Comparator<UnicornPointer>() {
            @Override
            public int compare(UnicornPointer o1, UnicornPointer o2) {
                return (int) (o1.peer - o2.peer);
            }
        });
        UnicornPointer first = list.get(0);
        UnicornPointer last = list.get(list.size() - 1);
        Alignment alignment = emulator.align(first.peer, last.peer - first.peer);
        final long base = alignment.address;
        final long size = alignment.size;

        Log log = LogFactory.getLog(MachOModule.class);
        if (log.isDebugEnabled()) {
            log.debug("createVirtualModule first=0x" + Long.toHexString(first.peer) + ", last=0x" + Long.toHexString(last.peer) + ", base=0x" + Long.toHexString(base) + ", size=0x" + Long.toHexString(size));
        }

        MachOModule module = new MachOModule(null, name, base, size, Collections.<String, Module>emptyMap(),
                Collections.<MemRegion>emptyList(),
                null, null, null,
                Collections.<NeedLibrary>emptyList(),
                Collections.<String, Module>emptyMap(),
                Collections.<String, Module>emptyMap(),
                name, emulator, null, null, null, null, 0L, false, null) {
            @Override
            public Symbol findSymbolByName(String name, boolean withDependencies) {
                UnicornPointer pointer = symbols.get(name);
                if (pointer != null) {
                    return new VirtualSymbol(name, this, pointer.peer);
                } else {
                    return null;
                }
            }
            @Override
            public void registerSymbol(String symbolName, long address) {
            }
            @Override
            public boolean isVirtual() {
                return true;
            }
        };
        for (Map.Entry<String, UnicornPointer> entry : symbols.entrySet()) {
            module.registerSymbol(entry.getKey(), entry.getValue().peer);
        }
        return module;
    }
}
