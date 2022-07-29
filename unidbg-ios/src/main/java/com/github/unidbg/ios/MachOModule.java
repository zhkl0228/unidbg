package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Alignment;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.Utils;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.ios.objc.ObjectiveCProcessor;
import com.github.unidbg.ios.objc.processor.CDObjectiveC2Processor;
import com.github.unidbg.ios.struct.DyldUnwindSections;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.VirtualSymbol;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MachOModule extends Module implements com.github.unidbg.ios.MachO {

    final Emulator<?> emulator;
    final MachO machO;
    final MachO.SymtabCommand symtabCommand;
    final MachO.DysymtabCommand dysymtabCommand;
    final ByteBuffer buffer;
    final List<NeedLibrary> lazyLoadNeededList;
    final Map<String, Module> upwardLibraries;
    final Map<String, Module> exportModules;
    private final String path;
    final MachO.DyldInfoCommand dyldInfoCommand;
    final MachO.LinkeditDataCommand chainedFixups;

    final List<InitFunction> routines;
    final List<InitFunction> initFunctionList;

    public final long machHeader;

    boolean indirectSymbolBound;
    boolean lazyPointerProcessed;

    private final Map<String, Symbol> symbolMap = new HashMap<>();

    private final Log log;

    final boolean executable;
    private final MachOLoader loader;
    private final List<HookListener> hookListeners;
    final List<String> ordinalList;

    private final Section fEHFrameSection;
    private final Section fUnwindInfoSection;
    public final Map<String, MachO.SegmentCommand64.Section64> objcSections;

    private final Map<String, ExportSymbol> exportSymbols;

    final Segment[] segments;

    private static final long ARM64E_MASK = 0x7ffffffffffL;

    private long offset2Virtual(long address) {
        for (Segment ph : segments) {
            if (address >= ph.fileOffset && address < (ph.fileOffset + ph.vmSize)) {
                return address + ph.vmAddr - ph.fileOffset;
            }
        }
        throw new UnsupportedOperationException("offset2Virtual address=0x" + Long.toHexString(address));
    }

    public final boolean validAddress(long address) {
        address &= ARM64E_MASK;
        for (Segment ph : segments) {
            if (ph.fileSize == 0) {
                continue;
            }
            if (address >= ph.vmAddr && address < (ph.vmAddr + ph.vmSize)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public final int virtualMemoryAddressToFileOffset(long address) {
        if (segments == null) {
            throw new UnsupportedOperationException();
        }
        boolean isPACCodePointer = (address & (3L << 62)) != 0;
        address &= ARM64E_MASK;

        if (isPACCodePointer) {
            long lower32Mask = -1L >>> 32;
            address = offset2Virtual(lower32Mask & address);
        }

        for (Segment ph : segments) {
            if (address >= ph.vmAddr && address < (ph.vmAddr + ph.vmSize)) {
                long relativeOffset = address - ph.vmAddr;
                if (relativeOffset >= ph.fileSize)
                    throw new IllegalStateException("Can not convert virtual memory address 0x" + Long.toHexString(address) + " to file offset -" + " found segment " + ph
                            + " but address maps to memory outside file range");
                long ret = ph.fileOffset + relativeOffset;
                if ((ret >> 33L) != 0) {
                    throw new IllegalStateException("ret=0x" + Long.toHexString(ret));
                }
                return (int) ret;
            }
        }
        throw new IllegalStateException("Cannot find segment for address: 0x" + Long.toHexString(address));
    }

    private final List<InitFunction> allInitFunctionList;

    MachOModule(MachO machO, String name, long base, long size, Map<String, Module> neededLibraries, List<MemRegion> regions,
                MachO.SymtabCommand symtabCommand, MachO.DysymtabCommand dysymtabCommand, ByteBuffer buffer,
                List<NeedLibrary> lazyLoadNeededList, Map<String, Module> upwardLibraries, Map<String, Module> exportModules,
                String path, Emulator<?> emulator, MachO.DyldInfoCommand dyldInfoCommand, MachO.LinkeditDataCommand chainedFixups, UnidbgPointer envp, UnidbgPointer apple, UnidbgPointer vars,
                long machHeader, boolean executable, MachOLoader loader, List<HookListener> hookListeners, List<String> ordinalList,
                Section fEHFrameSection, Section fUnwindInfoSection,
                Map<String, MachO.SegmentCommand64.Section64> objcSections,
                Segment[] segments, LibraryFile libraryFile) {
        super(name, base, size, neededLibraries, regions, libraryFile);
        this.emulator = emulator;
        this.machO = machO;
        this.symtabCommand = symtabCommand;
        this.dysymtabCommand = dysymtabCommand;
        this.buffer = buffer;
        this.lazyLoadNeededList = lazyLoadNeededList;
        this.upwardLibraries = upwardLibraries;
        this.exportModules = exportModules;
        this.path = path;
        this.dyldInfoCommand = dyldInfoCommand;
        this.chainedFixups = chainedFixups;
        this.envp = envp;
        this.apple = apple;
        this.vars = vars;
        this.machHeader = machHeader;
        this.executable = executable;
        this.loader = loader;
        this.hookListeners = hookListeners;
        this.ordinalList = ordinalList;
        this.fEHFrameSection = fEHFrameSection;
        this.fUnwindInfoSection = fUnwindInfoSection;
        this.objcSections = objcSections;
        this.segments = segments;

        this.log = LogFactory.getLog("com.github.unidbg.ios." + name);
        this.routines = machO == null ? Collections.<InitFunction>emptyList() : parseRoutines(machO);
        this.initFunctionList = machO == null ? Collections.<InitFunction>emptyList() : parseInitFunction(machO, buffer.duplicate(), name, emulator);
        List<InitFunction> allInitFunctionList = new ArrayList<>(routines.size() + initFunctionList.size());
        allInitFunctionList.addAll(routines);
        allInitFunctionList.addAll(initFunctionList);
        this.allInitFunctionList = Collections.unmodifiableList(allInitFunctionList);

        if (machO == null) {
            exportSymbols = Collections.emptyMap();
            return;
        }

        exportSymbols = processExportNode(log, dyldInfoCommand, buffer);

        if (symtabCommand != null) {
            buffer.limit((int) (symtabCommand.strOff() + symtabCommand.strSize()));
            buffer.position((int) symtabCommand.strOff());
            ByteBuffer strBuffer = buffer.slice();
            try (ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(strBuffer)) {
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
                        if (exportSymbols.isEmpty() || (exportSymbol = exportSymbols.remove(symbolName)) != null) {
                            if (log.isDebugEnabled()) {
                                log.debug("nlist un=0x" + Long.toHexString(nlist.un()) + ", symbolName=" + symbolName + ", type=0x" + Long.toHexString(nlist.type()) + ", isWeakDef=" + isWeakDef + ", isThumb=" + isThumb + ", value=0x" + Long.toHexString(nlist.value()));
                            }

                            MachOSymbol symbol = new MachOSymbol(this, nlist, symbolName);
                            if (exportSymbol != null && symbol.getAddress() == exportSymbol.getOtherWithBase()) {
                                if (log.isDebugEnabled()) {
                                    log.debug("nlist un=0x" + Long.toHexString(nlist.un()) + ", symbolName=" + symbolName + ", value=0x" + Long.toHexString(nlist.value()) + ", address=0x" + Long.toHexString(exportSymbol.getValue()) + ", other=0x" + Long.toHexString(exportSymbol.getOtherWithBase()));
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
                    } else if (log.isDebugEnabled()) {
                        log.debug("nlist isWeakDef=" + isWeakDef + ", isThumb=" + isThumb + ", type=" + type + ", symbolName=" + symbolName);
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public boolean hasWeakDefines() {
        return machO != null && (machO.header().flags() & com.github.unidbg.ios.MachO.MH_WEAK_DEFINES) != 0;
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
            UnidbgPointer sp = memory.allocateStack(0);
            byte[] data = sp.getByteArray(0, (int) (stack.peer - sp.peer));
            Inspector.inspect(data, "callEntry sp=0x" + Long.toHexString(memory.getStackPoint()) + ", envPointer=" + envPointer + ", auxvPointer=" + auxvPointer);
        }

        Pointer argvPointer = memory.allocateStack(0);
        return emulateFunction(emulator, machHeader + entryPoint, argc, argvPointer, envPointer, auxvPointer).intValue();
    }

    private boolean initialized;

    final void doInitialization(Emulator<?> emulator) {
        try {
            if (initialized) {
                return;
            }

            if (loader.executableModule == null) {
                vars.setPointer(0, UnidbgPointer.pointer(emulator, machHeader)); // _NSGetMachExecuteHeader
            }

            callRoutines(emulator);
            for (Module module : neededLibraries.values()) {
                MachOModule mm = (MachOModule) module;
                mm.doInitialization(emulator);
            }
            callInitFunction(emulator);
        } finally {
            initialized = true;
        }
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
            map.put(symbolName, new ExportSymbol(symbolName, address, this, other, flags));
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

    public final String findSymbolNameByAddress(long address) {
        if (dyldInfoCommand.bindSize() > 0) {
            ByteBuffer buffer = this.buffer.duplicate();
            buffer.limit((int) (dyldInfoCommand.bindOff() + dyldInfoCommand.bindSize()));
            buffer.position((int) dyldInfoCommand.bindOff());
            return findSymbol(buffer.slice(), address);
        } else {
            return null;
        }
    }

    private String findSymbol(ByteBuffer buffer, long findAddress) {
        final List<MemRegion> regions = this.getRegions();
        int segmentIndex;
        long address = this.base;
        long segmentEndAddress = address + this.size;
        String symbolName = null;
        int count;
        int skip;
        boolean done = false;
        while (!done && buffer.hasRemaining()) {
            int b = buffer.get() & 0xff;
            int immediate = b & BIND_IMMEDIATE_MASK;
            int opcode = b & BIND_OPCODE_MASK;
            switch (opcode) {
                case BIND_OPCODE_DONE:
                    done = true;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                case BIND_OPCODE_SET_TYPE_IMM:
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                case BIND_OPCODE_SET_ADDEND_SLEB:
                    Utils.readULEB128(buffer);
                    break;
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                    // the special ordinals are negative numbers
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    while ((b = buffer.get()) != 0) {
                        baos.write(b);
                    }
                    symbolName = baos.toString();
                    break;
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    segmentIndex = immediate;
                    if (segmentIndex >= regions.size()) {
                        throw new IllegalStateException(String.format("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (0..%d)", segmentIndex, regions.size() - 1));
                    }
                    MemRegion region = regions.get(segmentIndex);
                    address = region.begin + Utils.readULEB128(buffer).longValue();
                    segmentEndAddress = region.end;
                    break;
                case BIND_OPCODE_ADD_ADDR_ULEB:
                    address += Utils.readULEB128(buffer).longValue();
                    break;
                case BIND_OPCODE_DO_BIND:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    if (address == findAddress) {
                        return symbolName;
                    }
                    address += emulator.getPointerSize();
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    if (address == findAddress) {
                        return symbolName;
                    }
                    address += (Utils.readULEB128(buffer).longValue() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    if (address == findAddress) {
                        return symbolName;
                    }
                    address += ((long) immediate *emulator.getPointerSize() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    count = Utils.readULEB128(buffer).intValue();
                    skip = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        if (address == findAddress) {
                            return symbolName;
                        }
                        address += (skip + emulator.getPointerSize());
                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("bad bind opcode 0x%s in bind info", Integer.toHexString(opcode)));
            }
        }
        return null;
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
                        parseInitFunction(buffer, libName, emulator, initFunctionList, section.flags(), section.size(), section.offset());
                    }
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    for (MachO.SegmentCommand64.Section64 section : segmentCommand64.sections()) {
                        parseInitFunction(buffer, libName, emulator, initFunctionList, section.flags(), section.size(), section.offset());
                    }
            }
        }
        return initFunctionList;
    }

    private void parseInitFunction(ByteBuffer buffer, String libName, Emulator<?> emulator, List<InitFunction> initFunctionList, long flags, long size, long offset) {
        long type = flags & SECTION_TYPE;
        if (type != S_MOD_INIT_FUNC_POINTERS) {
            return;
        }

        long elementCount = size / emulator.getPointerSize();
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.limit((int) (offset + size));
        buffer.position((int) offset);
        for (int i = 0; i < elementCount; i++) {
            long address = emulator.is32Bit() ? buffer.getInt() : buffer.getLong();
            if (log.isDebugEnabled()) {
                log.debug("parseInitFunction libName=" + libName + ", address=0x" + Long.toHexString(address) + ", offset=0x" + Long.toHexString(offset) + ", elementCount=" + elementCount);
            }
            initFunctionList.add(new MachOModuleInit(this, envp, apple, vars, true, address));
        }
    }

    private final UnidbgPointer envp;
    private final UnidbgPointer apple;
    private final UnidbgPointer vars;

    final Map<String, Module> neededLibraries() {
        return neededLibraries;
    }

    @Override
    public Number callFunction(Emulator<?> emulator, long offset, Object... args) {
        return emulateFunction(emulator, base + offset, args);
    }

    MachOSymbol getSymbolByIndex(int index) {
        buffer.limit((int) (symtabCommand.strOff() + symtabCommand.strSize()));
        buffer.position((int) symtabCommand.strOff());
        ByteBuffer strBuffer = buffer.slice();

        try (ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(strBuffer)) {
            MachO.SymtabCommand.Nlist nlist = symtabCommand.symbols().get(index);
            strBuffer.position((int) nlist.un());
            String symbolName = new String(io.readBytesTerm(0, false, true, true), StandardCharsets.US_ASCII);
            return new MachOSymbol(this, nlist, symbolName);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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
        if (symbol == null) {
            ExportSymbol es = exportSymbols.get(name);
            if (es != null && !es.isReExport()) {
                symbol = es;
            }
        }
        if (symbol != null) {
            return symbol;
        }

        if (withDependencies) {
            Set<Module> findSet = new LinkedHashSet<>(loader.getLoadedModules().size());
            findSet.addAll(exportModules.values());
            findSet.addAll(upwardLibraries.values());
            findSet.addAll(neededLibraries.values());
//            findSet.addAll(loader.getLoadedModules());
            for (Module module : findSet) {
                symbol = module.findSymbolByName(name, false);
                if (symbol != null) {
                    return symbol;
                }
            }
        } else {
            for (Module module : exportModules.values()) {
                symbol = module.findSymbolByName(name, false);
                if (symbol != null) {
                    return symbol;
                }
            }
        }

        return null;
    }

    private ObjectiveCProcessor objectiveCProcessor;

    @Override
    public Symbol findClosestSymbolByAddress(long addr, boolean fast) {
        long targetAddress = addr - base;
        if (targetAddress == 0) {
            return new ExportSymbol("__dso_handle", addr, this, 0, EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE);
        }
        if (targetAddress < 0) {
            return null;
        }

        List<MachO.SymtabCommand.Nlist> symbols = symtabCommand.symbols();
        MachO.SymtabCommand.Nlist bestSymbol = null;

        // first walk all global symbols
        for (long i = dysymtabCommand.iExtDefSym(); i < dysymtabCommand.iExtDefSym() + dysymtabCommand.nExtDefSym(); i++) {
            MachO.SymtabCommand.Nlist nlist = symbols.get((int) i);
            if ((nlist.type() & N_TYPE) == N_SECT) {
                if ( bestSymbol == null ) {
                    if ( nlist.value() <= targetAddress ) {
                        bestSymbol = nlist;
                    }
                } else if ( (nlist.value() <= targetAddress) && (bestSymbol.value() < nlist.value()) ) {
                    bestSymbol = nlist;
                }
            }
        }

        // next walk all local symbols
        for (long i = dysymtabCommand.iLocalSym(); i < dysymtabCommand.iLocalSym() + dysymtabCommand.nLocalSym(); i++) {
            MachO.SymtabCommand.Nlist nlist = symbols.get((int) i);
            if ((nlist.type() & N_TYPE) == N_SECT && ((nlist.type() & N_STAB) == 0)) {
                if ( bestSymbol == null ) {
                    if ( nlist.value() <= targetAddress ) {
                        bestSymbol = nlist;
                    }
                } else if ( (nlist.value() <= targetAddress) && (bestSymbol.value() < nlist.value()) ) {
                    bestSymbol = nlist;
                }
            }
        }

        Symbol symbol = null;
        if (bestSymbol != null) {
            buffer.limit((int) (symtabCommand.strOff() + symtabCommand.strSize()));
            buffer.position((int) symtabCommand.strOff());
            ByteBuffer strBuffer = buffer.slice();
            strBuffer.position((int) bestSymbol.un());

            try (ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(strBuffer)) {
                String symbolName = new String(io.readBytesTerm(0, false, true, true), StandardCharsets.US_ASCII);
                // strip off leading underscore
                if (symbolName.startsWith("_")) {
                    symbolName = symbolName.substring(1);
                }
                symbol = new MachOSymbol(this, bestSymbol, symbolName);
                // never return the mach_header symbol
                if ((symbol.getAddress() & ~1) == base) {
                    return null;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        try {
            if (!fast && objectiveCProcessor == null && objcSections != null && !objcSections.isEmpty()) {
                objectiveCProcessor = new CDObjectiveC2Processor(this, emulator, buffer);
            }
            if (!fast && objectiveCProcessor != null) {
                if (executable) {
                    long entry = machHeader + entryPoint;
                    if (addr >= entry && (symbol == null || entry > symbol.getAddress())) {
                        symbol = new ExportSymbol("main", entry, this, 0, com.github.unidbg.ios.MachO.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE);
                    }
                }
                for (int i = 0; i < allInitFunctionList.size(); i++) {
                    InitFunction initFunction = allInitFunctionList.get(i);
                    long address = initFunction.getAddress();
                    if (addr >= address && (symbol == null || address > symbol.getAddress())) {
                        symbol = new ExportSymbol("InitFunc_" + i, address, this, 0, com.github.unidbg.ios.MachO.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE);
                    }
                }

                symbol = objectiveCProcessor.findObjcSymbol(symbol, targetAddress, this);
            }
        } catch (Exception e) {
            if (LogFactory.getLog(AbstractEmulator.class).isDebugEnabled()) {
                e.printStackTrace();
            }
        }

        return symbol;
    }

    @Override
    public String toString() {
        return path;
    }

    boolean hasUnresolvedSymbol() {
        return !allSymbolBound || !allLazySymbolBound;
    }

    boolean allSymbolBound;
    boolean allLazySymbolBound;

    final Set<UnidbgPointer> addImageCallSet = new HashSet<>();
    final Set<UnidbgPointer> boundCallSet = new HashSet<>();
    final Set<UnidbgPointer> dependentsInitializedCallSet = new HashSet<>();
    final Set<UnidbgPointer> initializedCallSet = new HashSet<>();

    boolean objcNotifyMapped;
    boolean objcNotifyInit;

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public void registerSymbol(String symbolName, long address) {
        throw new UnsupportedOperationException();
    }

    static MachOModule createVirtualModule(String name, final Map<String, UnidbgPointer> symbols, Emulator<?> emulator) {
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
                name, emulator, null, null, null, null, null, 0L, false, null,
                Collections.<HookListener>emptyList(), Collections.<String>emptyList(), null, null, null, null, null) {
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
            public void registerSymbol(String symbolName, long address) {
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

    public long doBindFastLazySymbol(Emulator<?> emulator, int lazyBindingInfoOffset) {
        ByteBuffer buffer = this.buffer.duplicate();
        buffer.limit((int) (dyldInfoCommand.lazyBindOff() + dyldInfoCommand.lazyBindSize()));
        buffer.position((int) dyldInfoCommand.lazyBindOff());
        return doBindFastLazySymbol(emulator, buffer.slice(), lazyBindingInfoOffset);
    }

    private long doBindFastLazySymbol(Emulator<?> emulator, ByteBuffer buffer, int lazyBindingInfoOffset) {
        final List<MemRegion> regions = this.getRegions();
        int type = BIND_TYPE_POINTER;
        long address = 0;
        String symbolName = null;
        int libraryOrdinal = 0;
        boolean done = false;
        long result = 0;
        buffer.position(lazyBindingInfoOffset);
        while (!done && buffer.hasRemaining()) {
            int b = buffer.get() & 0xff;
            int immediate = b & BIND_IMMEDIATE_MASK;
            int opcode = b & BIND_OPCODE_MASK;
            switch (opcode) {
                case BIND_OPCODE_DONE:
                    done = true;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                    libraryOrdinal = immediate;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                    libraryOrdinal = Utils.readULEB128(buffer).intValue();
                    break;
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                    // the special ordinals are negative numbers
                    if ( immediate == 0 )
                        libraryOrdinal = 0;
                    else {
                        libraryOrdinal = BIND_OPCODE_MASK | immediate;
                    }
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    while ((b = buffer.get()) != 0) {
                        baos.write(b);
                    }
                    symbolName = baos.toString();
                    break;
                case BIND_OPCODE_SET_TYPE_IMM:
                    type = immediate;
                    break;
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    MemRegion region = regions.get(immediate);
                    address = region.begin + Utils.readULEB128(buffer).longValue();
                    break;
                case BIND_OPCODE_DO_BIND:
                    result = bindAt(emulator, libraryOrdinal, type, address, symbolName);
                    break;
                case BIND_OPCODE_SET_ADDEND_SLEB:
                case BIND_OPCODE_ADD_ADDR_ULEB:
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                default:
                    throw new IllegalStateException("bad lazy bind opcode " + opcode);
            }
        }
        return result;
    }

    private long bindAt(Emulator<?> emulator, int libraryOrdinal, int type, long address, String symbolName) {
        libraryOrdinal = (byte) libraryOrdinal;
        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalStateException();
        }

        final MachOModule targetImage;
        if (libraryOrdinal == BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE) {
            targetImage = (MachOModule) loader.getExecutableModule();
        } else if (libraryOrdinal == BIND_SPECIAL_DYLIB_SELF) {
            targetImage = this;
        } else if (libraryOrdinal == BIND_SPECIAL_DYLIB_FLAT_LOOKUP) {
            for(MachOModule mm : loader.modules.values().toArray(new MachOModule[0])) {
                long at = bindAt(type, pointer, mm, symbolName, false);
                if (at != 0) {
                    return at;
                }
            }
            return 0;
        } else if (libraryOrdinal <= 0) {
            throw new IllegalStateException(String.format("bad mach-o binary, unknown special library ordinal (%d) too big for symbol %s in %s", libraryOrdinal, symbolName, getPath()));
        } else if (libraryOrdinal <= ordinalList.size()) {
            String path = ordinalList.get(libraryOrdinal - 1);
            targetImage = loader.modules.get(FilenameUtils.getName(path));
            if (targetImage == null) {
                throw new IllegalStateException("targetImage is null: path=" + path + ", module=" + getPath() + ", symbolName=" + symbolName);
            }
        } else {
            throw new IllegalStateException(String.format("bad mach-o binary, library ordinal (%d) too big (max %d) for symbol %s in %s", libraryOrdinal, ordinalList.size(), symbolName, getPath()));
        }

        if ("_dispatch_queue_create_with_target$V2".equals(symbolName)) {
            symbolName = "_dispatch_queue_create";
        }

        return bindAt(type, pointer, targetImage, symbolName, true);
    }

    private long bindAt(int type, Pointer pointer, MachOModule targetImage, String symbolName, boolean withDependencies) {
        Symbol symbol = targetImage.findSymbolByName(symbolName, withDependencies);
        if (symbol == null) {
            long bindAt = 0;
            for (HookListener listener : hookListeners) {
                long hook = listener.hook(emulator.getSvcMemory(), this.name, symbolName, HookListener.WEAK_BIND);
                if (hook > 0) {
                    bindAt = hook;
                    break;
                }
            }
            if (bindAt > 0) {
                Pointer newPointer = UnidbgPointer.pointer(emulator, bindAt);
                switch (type) {
                    case BIND_TYPE_POINTER:
                        pointer.setPointer(0, newPointer);
                        break;
                    case BIND_TYPE_TEXT_ABSOLUTE32:
                    case BIND_TYPE_TEXT_PCREL32:
                    default:
                        throw new IllegalStateException("bad bind type " + type);
                }
                return bindAt;
            }
            if (withDependencies) {
                log.info("bindAt type=" + type + ", symbolName=" + symbolName + ", upwardLibraries=" + this.upwardLibraries.values() + ", module=" + this.name + ", targetImage=" + targetImage);
            }
            return 0;
        }

        long bindAt = symbol.getAddress();
        for (HookListener listener : hookListeners) {
            long hook = listener.hook(emulator.getSvcMemory(), symbol.getModuleName(), symbol.getName(), bindAt);
            if (hook > 0) {
                bindAt = hook;
                break;
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("bindAt 0x=" + Long.toHexString(symbol.getValue()) + ", type=" + type + ", symbolName=" + symbol.getModuleName() + ", symbol=" + symbol + ", pointer=" + pointer + ", bindAt=0x" + Long.toHexString(bindAt));
        }

        switch (type) {
            case BIND_TYPE_POINTER:
                Pointer newPointer = UnidbgPointer.pointer(emulator, bindAt);
                pointer.setPointer(0, newPointer);
                break;
            case BIND_TYPE_TEXT_ABSOLUTE32:
                pointer.setInt(0, (int) (bindAt));
                break;
            case BIND_TYPE_TEXT_PCREL32:
            default:
                throw new IllegalStateException("bad bind type " + type);
        }
        return bindAt;
    }

    public final void getUnwindInfo(DyldUnwindSections info) {
        info.mach_header = machHeader;
        info.dwarf_section = 0;
        info.dwarf_section_length = 0;
        info.compact_unwind_section = 0;
        info.compact_unwind_section_length = 0;
        if (fEHFrameSection != null) {
            info.dwarf_section = base + fEHFrameSection.addr;
            info.dwarf_section_length = fEHFrameSection.size;
        }
        if (fUnwindInfoSection != null) {
            info.compact_unwind_section = base + fUnwindInfoSection.addr;
            info.compact_unwind_section_length = fUnwindInfoSection.size;
        }
        info.pack();
    }

    @Override
    public long getBaseHeader() {
        return machHeader;
    }

    final void callObjcNotifyMapped(UnidbgPointer _objcNotifyMapped) {
        if (_objcNotifyMapped != null && !objcNotifyMapped) {
            SvcMemory svcMemory = emulator.getSvcMemory();
            MemoryBlock block = emulator.getMemory().malloc(emulator.getPointerSize() * 2, true);
            try {
                Pointer paths = block.getPointer();
                Pointer mh = paths.share(emulator.getPointerSize());
                paths.setPointer(0, createPathMemory(svcMemory));
                mh.setPointer(0, UnidbgPointer.pointer(emulator, machHeader));
                Module.emulateFunction(emulator, _objcNotifyMapped.peer, 1, paths, mh);
                objcNotifyMapped = true;
            } finally {
                block.free();
            }
        }
    }

    final void callObjcNotifyInit(UnidbgPointer _objcNotifyInit) {
        if (_objcNotifyInit != null && !objcNotifyInit && objcNotifyMapped) {
            SvcMemory svcMemory = emulator.getSvcMemory();
            Module.emulateFunction(emulator, _objcNotifyInit.peer, createPathMemory(svcMemory), machHeader);
            objcNotifyInit = true;
        }
    }
}
