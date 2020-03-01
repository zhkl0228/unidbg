package com.github.unidbg.linux;

import com.github.unidbg.*;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.ElfLibraryFile;
import com.github.unidbg.memory.*;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.spi.AbstractLoader;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.spi.Loader;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import net.fornwall.jelf.*;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class AndroidElfLoader extends AbstractLoader<AndroidFileIO> implements Memory, Loader {

    private static final Log log = LogFactory.getLog(AndroidElfLoader.class);

    private Symbol malloc, free;

    public AndroidElfLoader(Emulator<AndroidFileIO> emulator, UnixSyscallHandler<AndroidFileIO> syscallHandler) {
        super(emulator, syscallHandler);

        // init stack
        stackSize = STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        unicorn.mem_map(STACK_BASE - stackSize, stackSize, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

        setStackPoint(STACK_BASE);
        initializeTLS(new String[] {
                "ANDROID_DATA=/data",
                "ANDROID_ROOT=/system"
        });
        this.setErrno(0);
    }

    @Override
    public void setLibraryResolver(LibraryResolver libraryResolver) {
        syscallHandler.addIOResolver((AndroidResolver) libraryResolver);
        super.setLibraryResolver(libraryResolver);
    }

    @Override
    protected LibraryFile createLibraryFile(File file) {
        return new ElfLibraryFile(file);
    }

    @Override
    public boolean hasThread(int threadId) {
        return syscallHandler.threadMap.containsKey(threadId);
    }

    @Override
    public void runLastThread(long timeout) {
        runThread(syscallHandler.lastThread, timeout);
    }

    @Override
    public void runThread(int threadId, long timeout) {
        try {
            emulator.setTimeout(timeout);
            LinuxThread thread = syscallHandler.threadMap.get(threadId);
            if (thread != null) {
                if (thread.context == 0) {
                    log.info("run thread: fn=" + thread.fn + ", arg=" + thread.arg + ", child_stack=" + thread.child_stack);
                    if (__thread_entry == 0) {
                        LinuxModule.emulateFunction(emulator, thread.fn.peer, thread.arg);
                    } else {
                        LinuxModule.emulateFunction(emulator, __thread_entry, thread.fn, thread.arg, thread.child_stack);
                    }
                } else {
                    unicorn.context_restore(thread.context);
                    long pc = ((Number) unicorn.reg_read(emulator.is32Bit() ? ArmConst.UC_ARM_REG_PC : Arm64Const.UC_ARM64_REG_PC)).intValue() & 0xffffffffL;
                    log.info("resume thread: fn=" + thread.fn + ", arg=" + thread.arg + ", child_stack=" + thread.child_stack + ", pc=0x" + Long.toHexString(pc));
                    unicorn.emu_start(pc, 0, 0, 0);
                }
                if (thread.context == 0) {
                    thread.context = unicorn.context_alloc();
                }
                unicorn.context_save(thread.context);
            } else {
                throw new IllegalStateException("thread: " + threadId + " not exits");
            }
        } finally {
            emulator.setTimeout(AbstractEmulator.DEFAULT_TIMEOUT);
        }
    }

    @Override
    public File dumpHeap() throws IOException {
        File outFile = File.createTempFile("heap_0x" + Long.toHexString(HEAP_BASE) + "_", ".dat");
        dump(UnicornPointer.pointer(emulator, HEAP_BASE), brk - HEAP_BASE, outFile);
        return outFile;
    }

    private void initializeTLS(String[] envs) {
        final Pointer thread = allocateStack(0x400); // reserve space for pthread_internal_t

        final Pointer __stack_chk_guard = allocateStack(emulator.getPointerSize());

        final Pointer programName = writeStackString(emulator.getProcessName());

        final Pointer programNamePointer = allocateStack(emulator.getPointerSize());
        assert programNamePointer != null;
        programNamePointer.setPointer(0, programName);

        final Pointer auxv = allocateStack(0x100);
        assert auxv != null;
        if (emulator.is32Bit()) {
            auxv.setInt(0, 25); // AT_RANDOM is a pointer to 16 bytes of randomness on the stack.
        } else {
            auxv.setLong(0, 25); // AT_RANDOM is a pointer to 16 bytes of randomness on the stack.
        }
        auxv.setPointer(emulator.getPointerSize(), __stack_chk_guard);

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

        final Pointer argv = allocateStack(0x100);
        assert argv != null;
        argv.setPointer(emulator.getPointerSize(), programNamePointer);
        argv.setPointer(2 * emulator.getPointerSize(), environ);
        argv.setPointer(3 * emulator.getPointerSize(), auxv);

        final UnicornPointer tls = allocateStack(0x80 * 4); // tls size
        assert tls != null;
        tls.setPointer(emulator.getPointerSize(), thread);
        this.errno = tls.share(emulator.getPointerSize() * 2);
        tls.setPointer(emulator.getPointerSize() * 3, argv);

        if (emulator.is32Bit()) {
            unicorn.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tls.peer);
        } else {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, tls.peer);
        }

        long sp = getStackPoint();
        sp &= (~(emulator.is64Bit() ? 15 : 7));
        setStackPoint(sp);

        if (log.isDebugEnabled()) {
            log.debug("initializeTLS tls=" + tls + ", argv=" + argv + ", auxv=" + auxv + ", thread=" + thread + ", environ=" + environ + ", sp=0x" + Long.toHexString(getStackPoint()));
        }
    }

    private final Map<String, LinuxModule> modules = new LinkedHashMap<>();

    protected final LinuxModule loadInternal(LibraryFile libraryFile, boolean forceCallInit) throws IOException {
        LinuxModule module = loadInternal(libraryFile);
        resolveSymbols();
        if (callInitFunction || forceCallInit) {
            for (LinuxModule m : modules.values().toArray(new LinuxModule[0])) {
                boolean forceCall = (forceCallInit && m == module) || m.isForceCallInit();
                if (callInitFunction) {
                    m.callInitFunction(emulator, forceCall);
                } else if(forceCall) {
                    m.callInitFunction(emulator, true);
                }
                m.initFunctionList.clear();
            }
        }
        module.addReferenceCount();
        return module;
    }

    private void resolveSymbols() throws IOException {
        for (LinuxModule m : modules.values()) {
            for (Iterator<ModuleSymbol> iterator = m.getUnresolvedSymbol().iterator(); iterator.hasNext(); ) {
                ModuleSymbol moduleSymbol = iterator.next();
                ModuleSymbol resolved = moduleSymbol.resolve(new HashSet<Module>(modules.values()), true, hookListeners, emulator.getSvcMemory());
                if (resolved != null) {
                    log.debug("[" + moduleSymbol.soName + "]" + moduleSymbol.symbol.getName() + " symbol resolved to " + resolved.toSoName);
                    resolved.relocation(emulator);
                    iterator.remove();
                } else {
                    log.info("[" + moduleSymbol.soName + "]symbol " + moduleSymbol.symbol + " is missing relocationAddr=" + moduleSymbol.relocationAddr + ", offset=0x" + Long.toHexString(moduleSymbol.offset));
                }
            }
        }
    }

    @Override
    public Module dlopen(String filename, boolean calInit) throws IOException {
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

        LinuxModule module = loadInternal(file);
        resolveSymbols();
        if (!callInitFunction) { // No need call init array
            for (LinuxModule m : modules.values()) {
                m.initFunctionList.clear();
            }
        }
        module.addReferenceCount();
        return module;
    }

    /**
     * dlopen调用init_array会崩溃
     */
    @Override
    public Module dlopen(String filename) throws IOException {
        return dlopen(filename, true);
    }

    @Override
    public Symbol dlsym(long handle, String symbolName) {
        for (LinuxModule module : modules.values()) {
            if (module.base == handle) { // virtual module may have same base address
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    return symbol;
                }
            }
        }
        return null;
    }

    @Override
    public boolean dlclose(long handle) {
        for (Iterator<Map.Entry<String, LinuxModule>> iterator = modules.entrySet().iterator(); iterator.hasNext(); ) {
            LinuxModule module = iterator.next().getValue();
            if (module.base == handle) {
                if (module.decrementReferenceCount() <= 0) {
                    module.unload(unicorn);
                    iterator.remove();
                }
                return true;
            }
        }
        return false;
    }

    private LinuxModule loadInternal(LibraryFile libraryFile) throws IOException {
        final ElfFile elfFile = ElfFile.fromBytes(libraryFile.readToByteArray());

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
        for (int i = 0; i < elfFile.num_ph; i++) {
            ElfSegment ph = elfFile.getProgramHeader(i);
            if (ph.type == ElfSegment.PT_LOAD && ph.mem_size > 0) {
                long high = ph.virtual_address + ph.mem_size;

                if (bound_high < high) {
                    bound_high = high;
                }
            }
        }

        ElfDynamicStructure dynamicStructure = null;

        final long baseAlign = emulator.getPageAlign();
        final long load_base = ((mmapBaseAddress - 1) / baseAlign + 1) * baseAlign;
        long size = emulator.align(0, bound_high).size;
        setMMapBaseAddress(load_base + size);

        final List<MemRegion> regions = new ArrayList<>(5);
        for (int i = 0; i < elfFile.num_ph; i++) {
            ElfSegment ph = elfFile.getProgramHeader(i);
            switch (ph.type) {
                case ElfSegment.PT_LOAD:
                    int prot = get_segment_protection(ph.flags);
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    final long begin = load_base + ph.virtual_address;
                    Alignment alignment = this.mem_map(begin, ph.mem_size, prot, libraryFile.getName());
                    unicorn.mem_write(begin, ph.getPtLoadData());

                    regions.add(new MemRegion(alignment.address, alignment.address + alignment.size, prot, libraryFile, ph.virtual_address));
                    break;
                case ElfSegment.PT_DYNAMIC:
                    dynamicStructure = ph.getDynamicStructure();
                    break;
                case ElfSegment.PT_INTERP:
                    if (log.isDebugEnabled()) {
                        log.debug("[" + libraryFile.getName() + "]interp=" + ph.getIntepreter());
                    }
                    break;
                default:
                    if (log.isDebugEnabled()) {
                        log.debug("[" + libraryFile.getName() + "]segment type=0x" + Integer.toHexString(ph.type) + ", offset=0x" + Long.toHexString(ph.offset));
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
            log.debug(soName + " need dependency " + neededLibrary);

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
                log.info(soName + " load dependency " + neededLibrary + " failed");
            }
        }

        for (LinuxModule module : modules.values()) {
            for (Iterator<ModuleSymbol> iterator = module.getUnresolvedSymbol().iterator(); iterator.hasNext(); ) {
                ModuleSymbol moduleSymbol = iterator.next();
                ModuleSymbol resolved = moduleSymbol.resolve(module.getNeededLibraries(), false, hookListeners, emulator.getSvcMemory());
                if (resolved != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("[" + moduleSymbol.soName + "]" + moduleSymbol.symbol.getName() + " symbol resolved to " + resolved.toSoName);
                    }
                    resolved.relocation(emulator);
                    iterator.remove();
                }
            }
        }

        List<ModuleSymbol> list = new ArrayList<>();
        for (MemoizedObject<ElfRelocation> object : dynamicStructure.getRelocations()) {
            ElfRelocation relocation = object.getValue();
            final int type = relocation.type();
            if (type == 0) {
                log.warn("Unhandled relocation type " + type);
                continue;
            }
            ElfSymbol symbol = relocation.sym() == 0 ? null : relocation.symbol();
            long sym_value = symbol != null ? symbol.value : 0;
            Pointer relocationAddr = UnicornPointer.pointer(emulator, load_base + relocation.offset());
            assert relocationAddr != null;

            Log log = LogFactory.getLog("com.github.unidbg.linux." + soName);
            if (log.isDebugEnabled()) {
                log.debug("symbol=" + symbol + ", type=" + type + ", relocationAddr=" + relocationAddr + ", offset=0x" + Long.toHexString(relocation.offset()) + ", addend=" + relocation.addend() + ", sym=" + relocation.sym() + ", android=" + relocation.isAndroid());
            }

            ModuleSymbol moduleSymbol;
            switch (type) {
                case ARMEmulator.R_ARM_ABS32: {
                    int offset = relocationAddr.getInt(0);
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), offset);
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, offset));
                    } else {
                        moduleSymbol.relocation(emulator);
                    }
                    break;
                }
                case ARMEmulator.R_AARCH64_ABS64: {
                    long offset = relocationAddr.getLong(0) + relocation.addend();
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), offset);
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, offset));
                    } else {
                        moduleSymbol.relocation(emulator);
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
                        moduleSymbol.relocation(emulator);
                    }
                    break;
                case ARMEmulator.R_AARCH64_GLOB_DAT:
                case ARMEmulator.R_AARCH64_JUMP_SLOT:
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), relocation.addend());
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, relocation.addend()));
                    } else {
                        moduleSymbol.relocation(emulator);
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
        if (elfFile.file_type == ElfFile.FT_EXEC) {
            int preInitArraySize = dynamicStructure.getPreInitArraySize();
            int count = preInitArraySize / emulator.getPointerSize();
            if (count > 0) {
                Pointer pointer = UnicornPointer.pointer(emulator, load_base + dynamicStructure.getPreInitArrayOffset());
                if (pointer == null) {
                    throw new IllegalStateException("DT_PREINIT_ARRAY is null");
                }
                for (int i = 0; i < count; i++) {
                    Pointer func = pointer.getPointer(i * emulator.getPointerSize());
                    if (func != null) {
                        initFunctionList.add(new AbsoluteInitFunction(load_base, soName, ((UnicornPointer) func).peer));
                    }
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
                Pointer pointer = UnicornPointer.pointer(emulator, load_base + dynamicStructure.getInitArrayOffset());
                if (pointer == null) {
                    throw new IllegalStateException("DT_INIT_ARRAY is null");
                }
                for (int i = 0; i < count; i++) {
                    Pointer func = pointer.getPointer(i * emulator.getPointerSize());
                    if (func != null) {
                        initFunctionList.add(new AbsoluteInitFunction(load_base, soName, ((UnicornPointer) func).peer));
                    }
                }
            }
        }

        SymbolLocator dynsym = dynamicStructure.getSymbolStructure();
        if (dynsym == null) {
            throw new IllegalStateException("dynsym is null");
        }
        LinuxModule module = new LinuxModule(load_base, size, soName, dynsym, list, initFunctionList, neededLibraries, regions);
        if ("libc.so".equals(soName)) { // libc
            ElfSymbol __thread_entry = module.getELFSymbolByName("__thread_entry");
            if (__thread_entry != null) {
                this.__thread_entry = module.base + __thread_entry.value;
            }

            malloc = module.findSymbolByName("malloc");
            free = module.findSymbolByName("free");
        }

        modules.put(soName, module);
        if (maxSoName == null || soName.length() > maxSoName.length()) {
            maxSoName = soName;
        }
        if (bound_high > maxSizeOfSo) {
            maxSizeOfSo = bound_high;
        }
        module.setEntryPoint(elfFile.entry_point);
        log.debug("Load library " + soName + " offset=" + (System.currentTimeMillis() - start) + "ms" + ", entry_point=0x" + Long.toHexString(elfFile.entry_point));
        notifyModuleLoaded(module);
        return module;
    }

    @Override
    public Module loadVirtualModule(String name, Map<String, UnicornPointer> symbols) {
        LinuxModule module = LinuxModule.createVirtualModule(name, symbols, emulator);
        modules.put(name, module);
        if (maxSoName == null || name.length() > maxSoName.length()) {
            maxSoName = name;
        }
        return module;
    }

    private long __thread_entry;

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
        if ((flags & /* PF_R= */4) != 0) prot |= Unicorn.UC_PROT_READ;
        if ((flags & /* PF_W= */2) != 0) prot |= Unicorn.UC_PROT_WRITE;
        if ((flags & /* PF_X= */1) != 0) prot |= Unicorn.UC_PROT_EXEC;
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
            unicorn.mem_map(brk, address - brk, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
            this.brk = address;
        } else if(address < brk) {
            unicorn.mem_unmap(address, brk - address);
            this.brk = address;
        }

        return (int) this.brk;
    }

    private Pointer errno;

    @Override
    public void setErrno(int errno) {
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
        return new ArrayList<Module>(modules.values());
    }
}
