package com.github.unidbg.linux;

import com.github.unidbg.Alignment;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.linux.android.ElfLibraryFile;
import com.github.unidbg.linux.thread.PThreadInternal;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryAllocBlock;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.MemoryBlockImpl;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.AbstractLoader;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.spi.Loader;
import com.github.unidbg.thread.Task;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.virtualmodule.VirtualSymbol;
import com.sun.jna.Pointer;
import net.fornwall.jelf.ArmExIdx;
import net.fornwall.jelf.ElfDynamicStructure;
import net.fornwall.jelf.ElfException;
import net.fornwall.jelf.ElfFile;
import net.fornwall.jelf.ElfRelocation;
import net.fornwall.jelf.ElfSection;
import net.fornwall.jelf.ElfSegment;
import net.fornwall.jelf.ElfSymbol;
import net.fornwall.jelf.GnuEhFrameHeader;
import net.fornwall.jelf.MemoizedObject;
import net.fornwall.jelf.PtLoadData;
import net.fornwall.jelf.SymbolLocator;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AndroidElfLoader extends AbstractLoader<AndroidFileIO> implements Memory, Loader {

    private static final Logger log = LoggerFactory.getLogger(AndroidElfLoader.class);

    private Symbol malloc, free;

    public AndroidElfLoader(Emulator<AndroidFileIO> emulator, UnixSyscallHandler<AndroidFileIO> syscallHandler) {
        super(emulator, syscallHandler);

        // init stack
        stackSize = STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        backend.mem_map(STACK_BASE - stackSize, stackSize, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

        setStackPoint(STACK_BASE);
        this.environ = initializeTLS(new String[] {
                "ANDROID_DATA=/data",
                "ANDROID_ROOT=/system",
                "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
                "NO_ADDR_COMPAT_LAYOUT_FIXUP=1"
        });
        this.setErrno(0);
    }

    @Override
    public void setLibraryResolver(LibraryResolver libraryResolver) {
        super.setLibraryResolver(libraryResolver);

        /*
         * 注意打开顺序很重要
         */
        syscallHandler.open(emulator, IO.STDIN, IOConstants.O_RDONLY);
        syscallHandler.open(emulator, IO.STDOUT, IOConstants.O_WRONLY);
        syscallHandler.open(emulator, IO.STDERR, IOConstants.O_WRONLY);
    }

    @Override
    protected LibraryFile createLibraryFile(File file) {
        return new ElfLibraryFile(file, emulator.is64Bit());
    }

    private UnidbgPointer initializeTLS(String[] envs) {
        final Pointer thread = allocateStack(0x400); // reserve space for pthread_internal_t
        PThreadInternal pThread = PThreadInternal.create(emulator, thread);
        pThread.tid = emulator.getPid();
        pThread.pack();

        final Pointer __stack_chk_guard = allocateStack(emulator.getPointerSize());

        final Pointer programName = writeStackString(emulator.getProcessName());

        final Pointer programNamePointer = allocateStack(emulator.getPointerSize());
        assert programNamePointer != null;
        programNamePointer.setPointer(0, programName);

        final Pointer auxv = allocateStack(0x100);
        assert auxv != null;
        final int AT_RANDOM = 25; // AT_RANDOM is a pointer to 16 bytes of randomness on the stack.
        auxv.setPointer(0, UnidbgPointer.pointer(emulator, AT_RANDOM));
        auxv.setPointer(emulator.getPointerSize(), __stack_chk_guard);
        final int AT_PAGESZ = 6;
        auxv.setPointer(emulator.getPointerSize() * 2L, UnidbgPointer.pointer(emulator, AT_PAGESZ));
        auxv.setPointer(emulator.getPointerSize() * 3L, UnidbgPointer.pointer(emulator, emulator.getPageAlign()));

        List<String> envList = new ArrayList<>();
        for (String env : envs) {
            int index = env.indexOf('=');
            if (index != -1) {
                envList.add(env);
            }
        }
        final Pointer environ = allocateStack(emulator.getPointerSize() * (envList.size() + 1));
        assert environ != null;
        Pointer pointer = environ;
        for (String env : envList) {
            Pointer envPointer = writeStackString(env);
            pointer.setPointer(0, envPointer);
            pointer = pointer.share(emulator.getPointerSize());
        }
        pointer.setPointer(0, null);

        final UnidbgPointer argv = allocateStack(0x100);
        assert argv != null;
        argv.setPointer(emulator.getPointerSize(), programNamePointer);
        argv.setPointer(2L * emulator.getPointerSize(), environ);
        argv.setPointer(3L * emulator.getPointerSize(), auxv);

        final UnidbgPointer tls = allocateStack(0x80 * 4); // tls size
        assert tls != null;
        tls.setPointer(emulator.getPointerSize(), thread);
        this.errno = tls.share(emulator.getPointerSize() * 2L);
        tls.setPointer(emulator.getPointerSize() * 3L, argv);

        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tls.peer);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, tls.peer);
        }

        long sp = getStackPoint();
        sp &= (~(emulator.is64Bit() ? 15 : 7));
        setStackPoint(sp);

        if (log.isDebugEnabled()) {
            log.debug("initializeTLS tls={}, argv={}, auxv={}, thread={}, environ={}, sp=0x{}", tls, argv, auxv, thread, environ, Long.toHexString(getStackPoint()));
        }
        return argv.share(2L * emulator.getPointerSize(), 0);
    }

    private final Map<String, LinuxModule> modules = new LinkedHashMap<>();

    protected final LinuxModule loadInternal(LibraryFile libraryFile, boolean forceCallInit) {
        try {
            LinuxModule module = loadInternal(libraryFile);
            resolveSymbols(!forceCallInit);
            if (callInitFunction || forceCallInit) {
                for (LinuxModule m : modules.values().toArray(new LinuxModule[0])) {
                    boolean forceCall = (forceCallInit && m == module) || m.isForceCallInit();
                    if (callInitFunction) {
                        m.callInitFunction(emulator, forceCall);
                    } else if (forceCall) {
                        m.callInitFunction(emulator, true);
                    }
                    m.initFunctionList.clear();
                }
            }
            module.addReferenceCount();
            return module;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private void resolveSymbols(boolean showWarning) throws IOException {
        Collection<LinuxModule> linuxModules = modules.values();
        for (LinuxModule m : linuxModules) {
            for (Iterator<ModuleSymbol> iterator = m.getUnresolvedSymbol().iterator(); iterator.hasNext(); ) {
                ModuleSymbol moduleSymbol = iterator.next();
                ModuleSymbol resolved = moduleSymbol.resolve(new HashSet<>(linuxModules), true, hookListeners, emulator.getSvcMemory());
                if (resolved != null) {
                    log.debug("resolveSymbols[{}]{} symbol resolved to {}", moduleSymbol.soName, moduleSymbol.symbol.getName(), resolved.toSoName);
                    resolved.relocation(emulator, m);
                    iterator.remove();
                } else if(showWarning) {
                    log.info("[{}]symbol {} is missing relocationAddr={}, offset=0x{}", moduleSymbol.soName, moduleSymbol.symbol, moduleSymbol.relocationAddr, Long.toHexString(moduleSymbol.offset));
                }
            }
        }
    }

    @Override
    public Module dlopen(String filename, boolean calInit) {
        LinuxModule loaded = modules.get(FilenameUtils.getName(filename));
        if (loaded != null) {
            loaded.addReferenceCount();
            return loaded;
        }

        for (Module module : getLoadedModules()) {
            for (MemRegion memRegion : module.getRegions()) {
                if (filename.equals(memRegion.getName())) {
                    module.addReferenceCount();
                    return module;
                }
            }
        }

        LibraryFile file = libraryResolver == null ? null : libraryResolver.resolveLibrary(emulator, filename);
        if (file == null) {
            return null;
        }

        if (calInit) {
            return loadInternal(file, false);
        }

        try {
            LinuxModule module = loadInternal(file);
            resolveSymbols(false);
            if (!callInitFunction) { // No need call init array
                for (LinuxModule m : modules.values()) {
                    m.initFunctionList.clear();
                }
            }
            module.addReferenceCount();
            return module;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * dlopen调用init_array会崩溃
     */
    @Override
    public Module dlopen(String filename) {
        return dlopen(filename, true);
    }

    private final UnidbgPointer environ;

    private static final int RTLD_DEFAULT = -1;

    @Override
    public Symbol dlsym(long handle, String symbolName) {
        if ("environ".equals(symbolName)) {
            return new VirtualSymbol(symbolName, null, environ.toUIntPeer());
        }
        Module sm = null;
        Symbol ret = null;
        for (LinuxModule module : modules.values()) {
            if (module.base == handle) { // virtual module may have same base address
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    ret = symbol;
                    sm = module;
                    break;
                }
            }
        }
        if (ret == null && ((int) handle == RTLD_DEFAULT || handle == 0L)) {
            for (Module module : modules.values()) {
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    ret = symbol;
                    sm = module;
                    break;
                }
            }
        }
        for (HookListener listener : hookListeners) {
            long hook = listener.hook(emulator.getSvcMemory(), sm == null ? null : sm.name, symbolName, ret == null ? 0L : ret.getAddress());
            if (hook != 0) {
                return new VirtualSymbol(symbolName, null, hook);
            }
        }
        return ret;
    }

    @Override
    public boolean dlclose(long handle) {
        for (Iterator<Map.Entry<String, LinuxModule>> iterator = modules.entrySet().iterator(); iterator.hasNext(); ) {
            LinuxModule module = iterator.next().getValue();
            if (module.base == handle) {
                if (module.decrementReferenceCount() <= 0) {
                    module.unload(backend);
                    iterator.remove();
                }
                return true;
            }
        }
        return false;
    }

    private LinuxModule loadInternal(LibraryFile libraryFile) throws IOException {
        final ElfFile elfFile = ElfFile.fromBuffer(libraryFile.mapBuffer());

        if (emulator.is32Bit() && elfFile.objectSize != ElfFile.CLASS_32) {
            throw new ElfException("Must be 32-bit");
        }
        if (emulator.is64Bit() && elfFile.objectSize != ElfFile.CLASS_64) {
            throw new ElfException("Must be 64-bit");
        }

        if (elfFile.encoding != ElfFile.DATA_LSB) {
            throw new ElfException("Must be LSB");
        }

        if (emulator.is32Bit() && elfFile.arch != ElfFile.ARCH_ARM) {
            throw new ElfException("Must be ARM arch.");
        }

        if (emulator.is64Bit() && elfFile.arch != ElfFile.ARCH_AARCH64) {
            throw new ElfException("Must be ARM64 arch.");
        }

        long start = System.currentTimeMillis();
        long bound_high = 0;
        long align = 0;
        for (int i = 0; i < elfFile.num_ph; i++) {
            ElfSegment ph = elfFile.getProgramHeader(i);
            if (ph.type == ElfSegment.PT_LOAD && ph.mem_size > 0) {
                long high = ph.virtual_address + ph.mem_size;

                if (bound_high < high) {
                    bound_high = high;
                }
                if (ph.alignment > align) {
                    align = ph.alignment;
                }
            }
        }

        ElfDynamicStructure dynamicStructure = null;

        final long baseAlign = Math.max(emulator.getPageAlign(), align);
        final long load_base = ((mmapBaseAddress - 1) / baseAlign + 1) * baseAlign;
        long load_virtual_address = 0;
        long size = ARM.align(0, bound_high, baseAlign).size;
        setMMapBaseAddress(load_base + size);

        final List<MemRegion> regions = new ArrayList<>(5);
        MemoizedObject<ArmExIdx> armExIdx = null;
        MemoizedObject<GnuEhFrameHeader> ehFrameHeader = null;
        Alignment lastAlignment = null;
        for (int i = 0; i < elfFile.num_ph; i++) {
            ElfSegment ph = elfFile.getProgramHeader(i);
            switch (ph.type) {
                case ElfSegment.PT_LOAD:
                    int prot = get_segment_protection(ph.flags);
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    final long begin = load_base + ph.virtual_address;
                    if (load_virtual_address == 0) {
                        load_virtual_address = begin;
                    }

                    Alignment check = ARM.align(begin, ph.mem_size, Math.max(emulator.getPageAlign(), ph.alignment));
                    final int regionSize = regions.size();
                    MemRegion last = regionSize == 0 ? null : regions.get(regionSize - 1);
                    MemRegion overall = null;
                    if (last != null && check.address >= last.begin && check.address < last.end) {
                        overall = last;
                    }
                    if (overall != null) {
                        long overallSize = overall.end - check.address;
                        int perms = overall.perms | prot;
                        if (mMapListener != null) {
                            perms = mMapListener.onProtect(check.address, overallSize, perms);
                        }
                        backend.mem_protect(check.address, overallSize, perms);
                        if (ph.mem_size > overallSize) {
                            Alignment alignment = this.mem_map(begin + overallSize, ph.mem_size - overallSize, prot, libraryFile.getName(), Math.max(emulator.getPageAlign(), ph.alignment));
                            regions.add(new MemRegion(begin, alignment.address, alignment.address + alignment.size, prot, libraryFile, ph.virtual_address));
                            if (lastAlignment != null && lastAlignment.begin + lastAlignment.dataSize > begin) {
                                throw new UnsupportedOperationException();
                            }
                            lastAlignment = alignment;
                            lastAlignment.begin = begin;
                        }
                    } else {
                        Alignment alignment = this.mem_map(begin, ph.mem_size, prot, libraryFile.getName(), Math.max(emulator.getPageAlign(), ph.alignment));
                        regions.add(new MemRegion(begin, alignment.address, alignment.address + alignment.size, prot, libraryFile, ph.virtual_address));
                        if (lastAlignment != null) {
                            long base = lastAlignment.address + lastAlignment.size;
                            long off = alignment.address - base;
                            if (off < 0) {
                                throw new IllegalStateException();
                            }
                            if (off > 0) {
                                backend.mem_map(base, off, UnicornConst.UC_PROT_NONE);
                                if (mMapListener != null) {
                                    mMapListener.onMap(base, off, UnicornConst.UC_PROT_NONE);
                                }
                                if (memoryMap.put(base, new MemoryMap(base, (int) off, UnicornConst.UC_PROT_NONE)) != null) {
                                    log.warn("mem_map replace exists memory map base={}", Long.toHexString(base));
                                }
                            }
                        }
                        lastAlignment = alignment;
                        lastAlignment.begin = begin;
                    }

                    PtLoadData loadData = ph.getPtLoadData();
                    loadData.writeTo(pointer(begin));
                    if (lastAlignment != null) {
                        lastAlignment.dataSize = loadData.getDataSize();
                    }
                    break;
                case ElfSegment.PT_DYNAMIC:
                    dynamicStructure = ph.getDynamicStructure();
                    break;
                case ElfSegment.PT_INTERP:
                    if (log.isDebugEnabled()) {
                        log.debug("[{}]interp={}", libraryFile.getName(), ph.getInterpreter());
                    }
                    break;
                case ElfSegment.PT_GNU_EH_FRAME:
                    ehFrameHeader = ph.getEhFrameHeader();
                    break;
                case ElfSegment.PT_ARM_EXIDX:
                    armExIdx = ph.getARMExIdxData();
                    break;
                default:
                    if (log.isDebugEnabled()) {
                        log.debug("[{}]segment type=0x{}, offset=0x{}", libraryFile.getName(), Integer.toHexString(ph.type), Long.toHexString(ph.offset));
                    }
                    break;
            }
        }

        if (dynamicStructure == null) {
            throw new IllegalStateException("dynamicStructure is empty.");
        }
        final String soName = dynamicStructure.getSOName(libraryFile.getName());

        Map<String, Module> neededLibraries = new HashMap<>();
        for (String neededLibrary : dynamicStructure.getNeededLibraries()) {
            if (log.isDebugEnabled()) {
                log.debug("{} need dependency {}", soName, neededLibrary);
            }

            LinuxModule loaded = modules.get(neededLibrary);
            if (loaded != null) {
                loaded.addReferenceCount();
                neededLibraries.put(FilenameUtils.getBaseName(loaded.name), loaded);
                continue;
            }
            LibraryFile neededLibraryFile = libraryFile.resolveLibrary(emulator, neededLibrary);
            if (libraryResolver != null && neededLibraryFile == null) {
                neededLibraryFile = libraryResolver.resolveLibrary(emulator, neededLibrary);
            }
            if (neededLibraryFile != null) {
                LinuxModule needed = loadInternal(neededLibraryFile);
                needed.addReferenceCount();
                neededLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
            } else {
                log.info("{} load dependency {} failed", soName, neededLibrary);
            }
        }

        for (LinuxModule module : modules.values()) {
            for (Iterator<ModuleSymbol> iterator = module.getUnresolvedSymbol().iterator(); iterator.hasNext(); ) {
                ModuleSymbol moduleSymbol = iterator.next();
                ModuleSymbol resolved = moduleSymbol.resolve(module.getNeededLibraries(), false, hookListeners, emulator.getSvcMemory());
                if (resolved != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("[{}]{} symbol resolved to {}", moduleSymbol.soName, moduleSymbol.symbol.getName(), resolved.toSoName);
                    }
                    resolved.relocation(emulator, module);
                    iterator.remove();
                }
            }
        }

        List<ModuleSymbol> list = new ArrayList<>();
        List<ModuleSymbol> resolvedSymbols = new ArrayList<>();
        for (MemoizedObject<ElfRelocation> object : dynamicStructure.getRelocations()) {
            ElfRelocation relocation = object.getValue();
            final int type = relocation.type();
            if (type == 0) {
                log.warn("Unhandled relocation type {}", type);
                continue;
            }
            ElfSymbol symbol = relocation.sym() == 0 ? null : relocation.symbol();
            long sym_value = symbol != null ? symbol.value : 0;
            Pointer relocationAddr = UnidbgPointer.pointer(emulator, load_base + relocation.offset());
            assert relocationAddr != null;

            Logger log = LoggerFactory.getLogger("com.github.unidbg.linux." + soName);
            if (log.isDebugEnabled()) {
                log.debug("symbol={}, type={}, relocationAddr={}, offset=0x{}, addend={}, sym={}, android={}", symbol, type, relocationAddr, Long.toHexString(relocation.offset()), relocation.addend(), relocation.sym(), relocation.isAndroid());
            }

            ModuleSymbol moduleSymbol;
            switch (type) {
                case ARMEmulator.R_ARM_ABS32: {
                    int offset = relocationAddr.getInt(0);
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), offset);
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, offset));
                    } else {
                        resolvedSymbols.add(moduleSymbol);
                    }
                    break;
                }
                case ARMEmulator.R_AARCH64_ABS64: {
                    long offset = relocationAddr.getLong(0) + relocation.addend();
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), offset);
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, offset));
                    } else {
                        resolvedSymbols.add(moduleSymbol);
                    }
                    break;
                }
                case ARMEmulator.R_ARM_RELATIVE: {
                    int offset = relocationAddr.getInt(0);
                    if (sym_value == 0) {
                        relocationAddr.setInt(0, (int) load_base + offset);
                    } else {
                        throw new IllegalStateException("sym_value=0x" + Long.toHexString(sym_value));
                    }
                    break;
                }
                case ARMEmulator.R_AARCH64_RELATIVE:
                    if (sym_value == 0) {
                        relocationAddr.setLong(0, load_base + relocation.addend());
                    } else {
                        throw new IllegalStateException("sym_value=0x" + Long.toHexString(sym_value));
                    }
                    break;
                case ARMEmulator.R_ARM_GLOB_DAT:
                case ARMEmulator.R_ARM_JUMP_SLOT:
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), 0);
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, 0));
                    } else {
                        resolvedSymbols.add(moduleSymbol);
                    }
                    break;
                case ARMEmulator.R_AARCH64_GLOB_DAT:
                case ARMEmulator.R_AARCH64_JUMP_SLOT:
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), relocation.addend());
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, relocation.addend()));
                    } else {
                        resolvedSymbols.add(moduleSymbol);
                    }
                    break;
                case ARMEmulator.R_ARM_COPY:
                    throw new IllegalStateException("R_ARM_COPY relocations are not supported");
                case ARMEmulator.R_AARCH64_COPY:
                    throw new IllegalStateException("R_AARCH64_COPY relocations are not supported");
                case ARMEmulator.R_AARCH64_ABS32:
                case ARMEmulator.R_AARCH64_ABS16:
                case ARMEmulator.R_AARCH64_PREL64:
                case ARMEmulator.R_AARCH64_PREL32:
                case ARMEmulator.R_AARCH64_PREL16:
                case ARMEmulator.R_AARCH64_IRELATIVE:
                case ARMEmulator.R_AARCH64_TLS_TPREL64:
                case ARMEmulator.R_AARCH64_TLS_DTPREL32:
                case ARMEmulator.R_ARM_IRELATIVE:
                case ARMEmulator.R_ARM_REL32:
                default:
                    log.warn("[" + soName + "]Unhandled relocation type " + type + ", symbol=" + symbol + ", relocationAddr=" + relocationAddr + ", offset=0x" + Long.toHexString(relocation.offset()) + ", addend=" + relocation.addend() + ", android=" + relocation.isAndroid());
                    break;
            }
        }

        List<InitFunction> initFunctionList = new ArrayList<>();
        int preInitArraySize = dynamicStructure.getPreInitArraySize();
        boolean executable = elfFile.file_type == ElfFile.FT_EXEC || preInitArraySize > 0;
        if (executable) {
            int count = preInitArraySize / emulator.getPointerSize();
            if (count > 0) {
                UnidbgPointer pointer = UnidbgPointer.pointer(emulator, load_base + dynamicStructure.getPreInitArrayOffset());
                if (pointer == null) {
                    throw new IllegalStateException("DT_PREINIT_ARRAY is null");
                }
                for (int i = 0; i < count; i++) {
                    UnidbgPointer ptr = pointer.share((long) i * emulator.getPointerSize(), 0);
                    initFunctionList.add(new AbsoluteInitFunction(load_base, soName, ptr));
                }
            }
        }
        if (elfFile.file_type == ElfFile.FT_DYN) { // not executable
            int init = dynamicStructure.getInit();
            if (init != 0) {
                initFunctionList.add(new LinuxInitFunction(load_base, soName, init));
            }

            int initArraySize = dynamicStructure.getInitArraySize();
            int count = initArraySize / emulator.getPointerSize();
            if (count > 0) {
                UnidbgPointer pointer = UnidbgPointer.pointer(emulator, load_base + dynamicStructure.getInitArrayOffset());
                if (pointer == null) {
                    throw new IllegalStateException("DT_INIT_ARRAY is null");
                }
                for (int i = 0; i < count; i++) {
                    UnidbgPointer ptr = pointer.share((long) i * emulator.getPointerSize(), 0);
                    initFunctionList.add(new AbsoluteInitFunction(load_base, soName, ptr));
                }
            }
        }

        SymbolLocator dynsym = dynamicStructure.getSymbolStructure();
        if (dynsym == null) {
            throw new IllegalStateException("dynsym is null");
        }
        ElfSection symbolTableSection = null;
        try {
            symbolTableSection = elfFile.getSymbolTableSection();
        } catch(Throwable ignored) {}
        if (load_virtual_address == 0) {
            throw new IllegalStateException("load_virtual_address");
        }
        LinuxModule module = new LinuxModule(load_virtual_address, load_base, size, soName, dynsym, list, initFunctionList, neededLibraries, regions,
                armExIdx, ehFrameHeader, symbolTableSection, elfFile, dynamicStructure, libraryFile);
        for (ModuleSymbol symbol : resolvedSymbols) {
            symbol.relocation(emulator, module);
        }
        if (executable) {
            for (LinuxModule linuxModule : modules.values()) {
                for (Map.Entry<String, ModuleSymbol> entry : linuxModule.resolvedSymbols.entrySet()) {
                    ElfSymbol symbol = module.getELFSymbolByName(entry.getKey());
                    if (symbol != null && !symbol.isUndef()) {
                        entry.getValue().relocation(emulator, module, symbol);
                    }
                }
                linuxModule.resolvedSymbols.clear();
            }
        }
        if ("libc.so".equals(soName)) { // libc
            malloc = module.findSymbolByName("malloc", false);
            free = module.findSymbolByName("free", false);
        }

        modules.put(soName, module);
        if (maxSoName == null || soName.length() > maxSoName.length()) {
            maxSoName = soName;
        }
        if (bound_high > maxSizeOfSo) {
            maxSizeOfSo = bound_high;
        }
        module.setEntryPoint(elfFile.entry_point);
        log.debug("Load library {} offset={}ms, entry_point=0x{}", soName, System.currentTimeMillis() - start, Long.toHexString(elfFile.entry_point));
        notifyModuleLoaded(module);
        return module;
    }

    @Override
    public Module loadVirtualModule(String name, Map<String, UnidbgPointer> symbols) {
        LinuxModule module = LinuxModule.createVirtualModule(name, symbols, emulator);
        modules.put(name, module);
        if (maxSoName == null || name.length() > maxSoName.length()) {
            maxSoName = name;
        }
        return module;
    }

    private String maxSoName;
    private long maxSizeOfSo;

    private ModuleSymbol resolveSymbol(long load_base, ElfSymbol symbol, Pointer relocationAddr, String soName, Collection<Module> neededLibraries, long offset) throws IOException {
        if (symbol == null) {
            return new ModuleSymbol(soName, load_base, null, relocationAddr, soName, offset);
        }

        if (!symbol.isUndef()) {
            for (HookListener listener : hookListeners) {
                long hook = listener.hook(emulator.getSvcMemory(), soName, symbol.getName(), load_base + symbol.value + offset);
                if (hook > 0) {
                    return new ModuleSymbol(soName, ModuleSymbol.WEAK_BASE, symbol, relocationAddr, soName, hook);
                }
            }
            return new ModuleSymbol(soName, load_base, symbol, relocationAddr, soName, offset);
        }

        return new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, offset).resolve(neededLibraries, false, hookListeners, emulator.getSvcMemory());
    }

    private int get_segment_protection(int flags) {
        int prot = Unicorn.UC_PROT_NONE;
        if ((flags & ElfSegment.PF_R) != 0) prot |= Unicorn.UC_PROT_READ;
        if ((flags & ElfSegment.PF_W) != 0) prot |= Unicorn.UC_PROT_WRITE;
        if ((flags & ElfSegment.PF_X) != 0) prot |= Unicorn.UC_PROT_EXEC;
        return prot;
    }

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        if (runtime) {
            return MemoryBlockImpl.alloc(this, length);
        } else {
            return MemoryAllocBlock.malloc(emulator, malloc, free, length);
        }
    }

    private static final long HEAP_BASE = 0x8048000;
    private long brk;

    @Override
    public int brk(long address) {
        if (address == 0) {
            this.brk = HEAP_BASE;
            return (int) this.brk;
        }

        if (address % emulator.getPageAlign() != 0) {
            throw new UnsupportedOperationException();
        }

        if (address > brk) {
            backend.mem_map(brk, address - brk, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
            if (mMapListener != null) {
                mMapListener.onMap(brk, address - brk, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
            }
            this.brk = address;
        } else if(address < brk) {
            backend.mem_unmap(address, brk - address);
            if (mMapListener != null) {
                mMapListener.onUnmap(address, brk - address);
            }
            this.brk = address;
        }

        return (int) this.brk;
    }

    private static final int MAP_FAILED = -1;
    public static final int MAP_FIXED = 0x10;
    public static final int MAP_ANONYMOUS = 0x20;

    @Override
    public long mmap2(long start, int length, int prot, int flags, int fd, int offset) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());

        boolean isAnonymous = ((flags & MAP_ANONYMOUS) != 0) || (start == 0 && fd <= 0 && offset == 0);
        if ((flags & MAP_FIXED) != 0 && isAnonymous) {
            if (log.isDebugEnabled()) {
                log.debug("mmap2 MAP_FIXED start=0x{}, length={}, prot={}", Long.toHexString(start), length, prot);
            }

            munmap(start, length);
            backend.mem_map(start, aligned, prot);
            if (mMapListener != null) {
                mMapListener.onMap(start, aligned, prot);
            }
            if (memoryMap.put(start, new MemoryMap(start, aligned, prot)) != null) {
                log.warn("mmap2 replace exists memory map: start={}", Long.toHexString(start));
            }
            return start;
        }
        if (isAnonymous) {
            long addr = allocateMapAddress(0, aligned);
            if (log.isDebugEnabled()) {
                log.debug("mmap2 addr=0x{}, mmapBaseAddress=0x{}, start={}, fd={}, offset={}, aligned={}, LR={}", Long.toHexString(addr), Long.toHexString(mmapBaseAddress), start, fd, offset, aligned, emulator.getContext().getLRPointer());
            }
            backend.mem_map(addr, aligned, prot);
            if (mMapListener != null) {
                mMapListener.onMap(start, aligned, prot);
            }
            if (memoryMap.put(addr, new MemoryMap(addr, aligned, prot)) != null) {
                log.warn("memoryMap mmap2 replace exists memory map addr={}", Long.toHexString(addr));
            }
            return addr;
        }
        try {
            FileIO file;
            if (start == 0 && fd > 0 && (file = syscallHandler.getFileIO(fd)) != null) {
                long addr = allocateMapAddress(0, aligned);
                if (log.isDebugEnabled()) {
                    log.debug("mmap2 addr=0x{}, mmapBaseAddress=0x{}", Long.toHexString(addr), Long.toHexString(mmapBaseAddress));
                }
                long ret = file.mmap2(emulator, addr, aligned, prot, offset, length);
                if (mMapListener != null) {
                    mMapListener.onMap(addr, aligned, prot);
                }
                if (memoryMap.put(addr, new MemoryMap(addr, aligned, prot)) != null) {
                    log.warn("mmap2 replace exists memory map addr=0x{}", Long.toHexString(addr));
                }
                return ret;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        try {
            FileIO file;
            if (fd > 0 && (file = syscallHandler.getFileIO(fd)) != null) {
                if ((start & (emulator.getPageAlign() - 1)) != 0) {
                    return MAP_FAILED;
                }
                long end = start + length;
                for (Map.Entry<Long, MemoryMap> entry : memoryMap.entrySet()) {
                    MemoryMap map = entry.getValue();
                    if (Math.max(start, entry.getKey()) <= Math.min(map.base + map.size, end)) {
                        return MAP_FAILED;
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("mmap2 start=0x{}, mmapBaseAddress=0x{}, flags=0x{}, length=0x{}", Long.toHexString(start), Long.toHexString(mmapBaseAddress), Integer.toHexString(flags), Integer.toHexString(length));
                }
                long ret = file.mmap2(emulator, start, aligned, prot, offset, length);
                if (mMapListener != null) {
                    mMapListener.onMap(start, aligned, prot);
                }
                if (memoryMap.put(start, new MemoryMap(start, aligned, prot)) != null) {
                    log.warn("mmap2 replace exists memory map start=0x{}", Long.toHexString(start));
                }
                return ret;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        emulator.attach().debug();
        throw new AbstractMethodError("mmap2 start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset);
    }

    private Pointer errno;

    private int lastErrno;

    @Override
    public int getLastErrno() {
        return lastErrno;
    }

    @Override
    public void setErrno(int errno) {
        this.lastErrno = errno;
        Task task = emulator.get(Task.TASK_KEY);
        if (task != null && task.setErrno(emulator, errno)) {
            return;
        }
        this.errno.setInt(0, errno);
    }

    @Override
    public String getMaxLengthLibraryName() {
        return maxSoName;
    }

    @Override
    public long getMaxSizeOfLibrary() {
        return maxSizeOfSo;
    }

    @Override
    public Collection<Module> getLoadedModules() {
        return new ArrayList<>(modules.values());
    }
}
