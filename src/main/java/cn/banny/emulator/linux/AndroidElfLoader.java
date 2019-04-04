package cn.banny.emulator.linux;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.*;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.hook.HookListener;
import cn.banny.emulator.linux.android.ElfLibraryFile;
import cn.banny.emulator.linux.file.FileIO;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.memory.MemoryBlockImpl;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import net.fornwall.jelf.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class AndroidElfLoader implements Memory, Loader {

    private static final Log log = LogFactory.getLog(AndroidElfLoader.class);

    private final Unicorn unicorn;
    private final Emulator emulator;
    private final AbstractSyscallHandler syscallHandler;
    private LibraryResolver libraryResolver;

    private long sp;

    private long mmapBaseAddress;

    private Symbol malloc;

    public AndroidElfLoader(Unicorn unicorn, Emulator emulator, AbstractSyscallHandler syscallHandler) {
        this.unicorn = unicorn;
        this.emulator = emulator;
        this.syscallHandler = syscallHandler;

        // init stack
        final long stackSize = STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        unicorn.mem_map(STACK_BASE - stackSize, stackSize, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

        mmapBaseAddress = MMAP_BASE;

        setStackPoint(STACK_BASE);
        initializeTLS();
        this.setErrno(0);
    }

    @Override
    public boolean hasThread(int threadId) {
        return syscallHandler.threadMap.containsKey(threadId);
    }

    @Override
    public void runLastThread() {
        runThread(syscallHandler.lastThread);
    }

    @Override
    public void runThread(int threadId) {
        LinuxThread thread = syscallHandler.threadMap.get(threadId);
        if (thread != null) {
            if (thread.context == 0) {
                log.info("run thread: fn=" + thread.fn + ", arg=" + thread.arg + ", child_stack=" + thread.child_stack);
                Module.emulateFunction(emulator, __thread_entry, thread.fn, thread.arg, thread.child_stack);
            } else {
                unicorn.context_restore(thread.context);
                long pc = ((Number) unicorn.reg_read(emulator.getPointerSize() == 4 ? ArmConst.UC_ARM_REG_PC : Arm64Const.UC_ARM64_REG_PC)).intValue() & 0xffffffffL;
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
    }

    @Override
    public File dumpHeap() throws IOException {
        File outFile = File.createTempFile("heap_0x" + Long.toHexString(HEAP_BASE) + "_", ".dat");
        dump(UnicornPointer.pointer(emulator, HEAP_BASE), brk - HEAP_BASE, outFile);
        return outFile;
    }

    @Override
    public File dumpStack() throws IOException {
        UnicornPointer sp = UnicornPointer.register(emulator, emulator.getPointerSize() == 4 ? ArmConst.UC_ARM_REG_SP : Arm64Const.UC_ARM64_REG_SP);
        File outFile = File.createTempFile("stack_0x" + Long.toHexString(sp.peer) + "_", ".dat");
        dump(sp, STACK_BASE - sp.peer, outFile);
        return outFile;
    }

    private void dump(Pointer pointer, long size, File outFile) throws IOException {
        FileOutputStream outputStream = null;
        try {
            outputStream = new FileOutputStream(outFile);

            int dump = 0;
            while (dump < size) {
                long read = size - dump;
                if (read > ARMEmulator.PAGE_ALIGN) {
                    read = ARMEmulator.PAGE_ALIGN;
                }
                byte[] data = pointer.getByteArray(dump, (int) read);
                outputStream.write(data);
                dump += read;
            }
        } finally {
            IOUtils.closeQuietly(outputStream);
        }
    }

    @Override
    public UnicornPointer allocateStack(int size) {
        setStackPoint(sp - size);
        UnicornPointer pointer = UnicornPointer.pointer(emulator, sp);
        assert pointer != null;
        return pointer.setSize(size);
    }

    @Override
    public UnicornPointer writeStackString(String str) {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        return writeStackBytes(Arrays.copyOf(data, data.length + 1));
    }

    @Override
    public UnicornPointer writeStackBytes(byte[] data) {
        int size = ARM.alignSize(data.length);
        UnicornPointer pointer = allocateStack(size);
        assert pointer != null;
        pointer.write(0, data, 0, data.length);
        return pointer;
    }

    @Override
    public UnicornPointer pointer(long address) {
        return UnicornPointer.pointer(emulator, address);
    }

    @Override
    public void setStackPoint(long sp) {
        this.sp = sp;
        if (emulator.getPointerSize() == 4) {
            unicorn.reg_write(ArmConst.UC_ARM_REG_SP, sp);
        } else {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_SP, sp);
        }
    }

    private void initializeTLS() {
        final Pointer thread = allocateStack(0x400); // reserve space for pthread_internal_t

        final Pointer __stack_chk_guard = allocateStack(emulator.getPointerSize());

        final Pointer programName = writeStackString(emulator.getProcessName());

        final Pointer programNamePointer = allocateStack(emulator.getPointerSize());
        assert programNamePointer != null;
        programNamePointer.setPointer(0, programName);

        final Pointer vector = allocateStack(0x100);
        assert vector != null;
        vector.setInt(0, 25); // AT_RANDOM is a pointer to 16 bytes of randomness on the stack.
        vector.setPointer(4, __stack_chk_guard);

        final Pointer environ = allocateStack(4);
        assert environ != null;
        environ.setInt(0, 0);

        final Pointer argv = allocateStack(0x100);
        assert argv != null;
        argv.setPointer(4, programNamePointer);
        argv.setPointer(8, environ);
        argv.setPointer(0xc, vector);

        final UnicornPointer tls = allocateStack(0x80 * 4); // tls size
        assert tls != null;
        tls.setPointer(emulator.getPointerSize(), thread);
        this.errno = tls.share(emulator.getPointerSize() * 2);
        tls.setPointer(emulator.getPointerSize() * 3, argv);

        if (emulator.getPointerSize() == 4) {
            unicorn.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tls.peer);
        } else {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, tls.peer);
        }
        log.debug("initializeTLS tls=" + tls + ", argv=" + argv + ", vector=" + vector + ", thread=" + thread + ", environ=" + environ);
    }

    @Override
    public void setLibraryResolver(LibraryResolver libraryResolver) {
        this.libraryResolver = libraryResolver;

        syscallHandler.addIOResolver(libraryResolver);

        /*
         * 注意打开顺序很重要
         */
        syscallHandler.open(emulator, STDIN, FileIO.O_RDONLY);
        syscallHandler.open(emulator, STDOUT, FileIO.O_WRONLY);
        syscallHandler.open(emulator, STDERR, FileIO.O_WRONLY);
    }

    private final Map<String, Module> modules = new LinkedHashMap<>();

    @Override
    public Module load(File elfFile) throws IOException {
        return load(elfFile,false);
    }

    @Override
    public Module load(File elfFile, boolean forceCallInit) throws IOException {
        return loadInternal(new ElfLibraryFile(elfFile), null, forceCallInit);
    }

    @Override
    public Module load(LibraryFile libraryFile) throws IOException {
        return load(libraryFile, false);
    }

    @Override
    public Module load(LibraryFile libraryFile, boolean forceCallInit) throws IOException {
        return loadInternal(libraryFile, null, forceCallInit);
    }

    @Override
    public byte[] unpack(File elfFile) throws IOException {
        final byte[] fileData = FileUtils.readFileToByteArray(elfFile);
        loadInternal(new ElfLibraryFile(elfFile), new WriteHook() {
            @Override
            public void hook(Unicorn u, long address, int size, long value, Object user) {
                byte[] data = Arrays.copyOf(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array(), size);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "### Unpack WRITE at 0x" + Long.toHexString(address));
                }
                System.arraycopy(data, 0, fileData, (int) address, data.length);
            }
        }, true);
        return fileData;
    }

    private Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook, boolean forceCallInit) throws IOException {
        Module module = loadInternal(libraryFile, unpackHook);
        resolveSymbols();
        if (callInitFunction || forceCallInit) {
            for (Module m : modules.values().toArray(new Module[0])) {
                boolean forceCall = forceCallInit && m == module;
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
        for (Module m : modules.values()) {
            for (Iterator<ModuleSymbol> iterator = m.getUnresolvedSymbol().iterator(); iterator.hasNext(); ) {
                ModuleSymbol moduleSymbol = iterator.next();
                ModuleSymbol resolved = moduleSymbol.resolve(modules.values(), true, hookListeners, emulator.getSvcMemory());
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

    private ModuleListener moduleListener;

    @Override
    public void setModuleListener(ModuleListener listener) {
        moduleListener = listener;
    }

    @Override
    public Module dlopen(String filename, boolean calInit) throws IOException {
        Module loaded = modules.get(FilenameUtils.getName(filename));
        if (loaded != null) {
            loaded.addReferenceCount();
            return loaded;
        }

        for (Module module : getLoadedModules()) {
            for (MemRegion memRegion : module.getRegions()) {
                if (filename.equals(memRegion.getName())) {
                    return module;
                }
            }
        }

        LibraryFile file = libraryResolver == null ? null : libraryResolver.resolveLibrary(emulator, filename);
        if (file == null) {
            return null;
        }

        if (calInit) {
            return loadInternal(file, null, false);
        }

        Module module = loadInternal(file, null);
        resolveSymbols();
        if (!callInitFunction) { // No need call init array
            for (Module m : modules.values()) {
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
    public Symbol dlsym(long handle, String symbol) throws IOException {
        for (Module module : modules.values()) {
            if (module.base == handle) {
                ElfSymbol elfSymbol = module.getELFSymbolByName(symbol);
                if (elfSymbol == null) {
                    return null;
                } else {
                    return new Symbol(module, elfSymbol);
                }
            }
        }
        return null;
    }

    @Override
    public boolean dlclose(long handle) {
        for (Iterator<Map.Entry<String, Module>> iterator = modules.entrySet().iterator(); iterator.hasNext(); ) {
            Module module = iterator.next().getValue();
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

    private Module loadInternal(LibraryFile libraryFile, final WriteHook unpackHook) throws IOException {
        final ElfFile elfFile = ElfFile.fromBytes(libraryFile.readToByteArray());

        if (emulator.getPointerSize() == 4 && elfFile.objectSize != ElfFile.CLASS_32) {
            throw new ElfException("Must be 32-bit");
        }
        if (emulator.getPointerSize() == 8 && elfFile.objectSize != ElfFile.CLASS_64) {
            throw new ElfException("Must be 64-bit");
        }

        if (elfFile.encoding != ElfFile.DATA_LSB) {
            throw new ElfException("Must be LSB");
        }

        if (emulator.getPointerSize() == 4 && elfFile.arch != ElfFile.ARCH_ARM) {
            throw new ElfException("Must be ARM arch.");
        }

        if (emulator.getPointerSize() == 8 && elfFile.arch != ElfFile.ARCH_AARCH64) {
            throw new ElfException("Must be ARM64 arch.");
        }

        long start = System.currentTimeMillis();
        long bound_low = 0;
        long bound_high = 0;
        for (int i = 0; i < elfFile.num_ph; i++) {
            ElfSegment ph = elfFile.getProgramHeader(i);
            if (ph.type == ElfSegment.PT_LOAD && ph.mem_size > 0) {
                if (bound_low > ph.virtual_address) {
                    bound_low = ph.virtual_address;
                }

                long high = ph.virtual_address + ph.mem_size;

                if (bound_high < high) {
                    bound_high = high;
                }
            }
        }

        ElfDynamicStructure dynamicStructure = null;

        final long baseAlign = emulator.getPageAlign();
        final long load_base = ((mmapBaseAddress - 1) / baseAlign + 1) * baseAlign;
        long size = emulator.align(0, bound_high - bound_low).size;
        mmapBaseAddress = load_base + size;

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
                    final long end = begin + ph.mem_size;
                    Alignment alignment = this.mem_map(begin, ph.mem_size, prot, libraryFile.getName());
                    unicorn.mem_write(begin, ph.getPtLoadData());

                    regions.add(new MemRegion(alignment.address, alignment.address + alignment.size, prot, libraryFile, ph.virtual_address));

                    if (unpackHook != null && (prot & UnicornConst.UC_PROT_EXEC) != 0) { // unpack executable code
                        unicorn.hook_add(new WriteHook() {
                            @Override
                            public void hook(Unicorn u, long address, int size, long value, Object user) {
                                if (address >= begin && address < end) {
                                    unpackHook.hook(u, address - load_base, size, value, user);
                                }
                            }
                        }, begin, end, null);
                    }

                    break;
                case ElfSegment.PT_DYNAMIC:
                    dynamicStructure = ph.getDynamicStructure();
                    break;
                case ElfSegment.PT_INTERP:
                    log.debug("[" + libraryFile.getName() + "]interp=" + ph.getIntepreter());
                    break;
                default:
                    log.debug("[" + libraryFile.getName() + "]segment type=0x" + Integer.toHexString(ph.type) + ", offset=0x" + Long.toHexString(ph.offset));
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

            Module loaded = modules.get(neededLibrary);
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
                Module needed = loadInternal(neededLibraryFile, null);
                needed.addReferenceCount();
                neededLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
            } else {
                log.info(soName + " load dependency " + neededLibrary + " failed");
            }
        }

        for (Module module : modules.values()) {
            for (Iterator<ModuleSymbol> iterator = module.getUnresolvedSymbol().iterator(); iterator.hasNext(); ) {
                ModuleSymbol moduleSymbol = iterator.next();
                ModuleSymbol resolved = moduleSymbol.resolve(module.getNeededLibraries(), false, hookListeners, emulator.getSvcMemory());
                if (resolved != null) {
                    log.debug("[" + moduleSymbol.soName + "]" + moduleSymbol.symbol.getName() + " symbol resolved to " + resolved.toSoName);
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

            if (relocation.isAndroid()) {
                Log log = LogFactory.getLog(soName);
                log.debug("symbol=" + symbol + ", type=" + type + ", relocationAddr=" + relocationAddr + ", offset=0x" + Long.toHexString(relocation.offset()) + ", addend=" + relocation.addend());
            }

            ModuleSymbol moduleSymbol;
            switch (type) {
                case ARMEmulator.R_ARM_ABS32:
                    long offset = relocationAddr.getInt(0);
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), offset);
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, offset));
                    } else {
                        moduleSymbol.relocation(emulator);
                    }
                    break;
                case ARMEmulator.R_AARCH64_ABS64:
                    offset = relocationAddr.getLong(0);
                    moduleSymbol = resolveSymbol(load_base, symbol, relocationAddr, soName, neededLibraries.values(), offset);
                    if (moduleSymbol == null) {
                        list.add(new ModuleSymbol(soName, load_base, symbol, relocationAddr, null, offset));
                    } else {
                        moduleSymbol.relocation(emulator);
                    }
                    break;
                case ARMEmulator.R_ARM_RELATIVE:
                    if (sym_value == 0) {
                        relocationAddr.setInt(0, (int) load_base + relocationAddr.getInt(0));
                    } else {
                        throw new IllegalStateException("sym_value=0x" + Long.toHexString(sym_value));
                    }
                    break;
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
                    log.warn("[" + soName + "]Unhandled relocation type " + type + ", symbol=" + symbol + ", relocationAddr=" + relocationAddr + ", offset=0x" + Long.toHexString(relocation.offset()) + ", addend=" + relocation.addend() + ", android=" + relocation.isAndroid());
                    break;
                default:
                    log.debug("[" + soName + "]Unhandled relocation type " + type + ", symbol=" + symbol + ", relocationAddr=" + relocationAddr + ", offset=0x" + Long.toHexString(relocation.offset()) + ", addend=" + relocation.addend() + ", android=" + relocation.isAndroid());
                    break;
            }
        }

        List<InitFunction> initFunctionList = new ArrayList<>();
        if (elfFile.file_type == ElfFile.FT_DYN) { // not executable
            int init = dynamicStructure.getInit();
            ElfInitArray preInitArray = dynamicStructure.getPreInitArray();
            ElfInitArray initArray = dynamicStructure.getInitArray();

            initFunctionList.add(new InitFunction(load_base, soName, init));

            if (preInitArray != null) {
                initFunctionList.add(new InitFunction(load_base, soName, preInitArray));
            }

            if (initArray != null) {
                initFunctionList.add(new InitFunction(load_base, soName, initArray));
            }
        }

        SymbolLocator dynsym = dynamicStructure.getSymbolStructure();
        if (dynsym == null) {
            throw new IllegalStateException("dynsym is null");
        }
        Module module = new Module(load_base, bound_high - bound_low, soName, dynsym, list, initFunctionList, neededLibraries, regions);
        if ("libc.so".equals(soName)) { // libc
            /*ElfSymbol __bionic_brk = module.getELFSymbolByName("__bionic_brk");
            if (__bionic_brk != null) {
                unicorn.mem_write(module.base + __bionic_brk.value, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) HEAP_BASE).array());
                brk = HEAP_BASE;
            }*/

            ElfSymbol __thread_entry = module.getELFSymbolByName("__thread_entry");
            if (__thread_entry != null) {
                this.__thread_entry = module.base + __thread_entry.value;
            }

            malloc = module.findSymbolByName("malloc");
        }

        modules.put(soName, module);
        if (maxSoName == null || soName.length() > maxSoName.length()) {
            maxSoName = soName;
        }
        if (bound_high - bound_low > maxSizeOfSo) {
            maxSizeOfSo = bound_high - bound_low;
        }
        module.setEntryPoint(elfFile.entry_point);
        log.debug("Load library " + soName + " offset=" + (System.currentTimeMillis() - start) + "ms" + ", entry_point=0x" + Long.toHexString(elfFile.entry_point));
        if (moduleListener != null) {
            moduleListener.onLoaded(emulator, module);
        }
        return module;
    }

    private long __thread_entry;

    private String maxSoName;
    private long maxSizeOfSo;

    private boolean callInitFunction;

    @Override
    public void setCallInitFunction() {
        this.callInitFunction = true;
    }

    @Override
    public Module findModuleByAddress(long address) {
        for (Module module : modules.values()) {
            if (address >= module.base && address < module.base + module.size) {
                return module;
            }
        }
        return null;
    }

    @Override
    public Module findModule(String soName) {
        for (Module module : modules.values()) {
            if (module.name.equals(soName)) {
                return module;
            }
        }
        return null;
    }

    private ModuleSymbol resolveSymbol(long load_base, ElfSymbol symbol, Pointer relocationAddr, String soName, Collection<Module> neededLibraries, long offset) throws IOException {
        if (symbol == null) {
            return new ModuleSymbol(soName, load_base, symbol, relocationAddr, soName, offset);
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

    private Alignment mem_map(long address, long size, int prot, String libraryName) {
        Alignment alignment = emulator.align(address, size);

        log.debug("[" + libraryName + "]0x" + Long.toHexString(alignment.address) + " - 0x" + Long.toHexString(alignment.address + alignment.size) + ", size=0x" + Long.toHexString(alignment.size));

        unicorn.mem_map(alignment.address, alignment.size, prot);
        memoryMap.put(alignment.address, (int) alignment.size);
        return alignment;
    }

    private int get_segment_protection(int flags) {
        int prot = Unicorn.UC_PROT_NONE;
        if ((flags & /* PF_R= */4) != 0) prot |= Unicorn.UC_PROT_READ;
        if ((flags & /* PF_W= */2) != 0) prot |= Unicorn.UC_PROT_WRITE;
        if ((flags & /* PF_X= */1) != 0) prot |= Unicorn.UC_PROT_EXEC;
        return prot;
    }

//    private static final int MAP_SHARED =	0x01;		/* Share changes */
//    private static final int MAP_PRIVATE =	0x02;		/* Changes are private */
//    private static final int MAP_TYPE =	0x0f;		/* Mask for type of mapping */
//    private static final int MAP_FIXED =	0x10;		/* Interpret addr exactly */
//    private static final int MAP_ANONYMOUS =	0x20;		/* don't use a file */

    private final Map<Long, Integer> memoryMap = new TreeMap<>();

    private long allocateMapAddress(int length) {
        Map.Entry<Long, Integer> lastEntry = null;
        for (Map.Entry<Long, Integer> entry : memoryMap.entrySet()) {
            if (lastEntry == null) {
                lastEntry = entry;
            } else {
                long mmapAddress = lastEntry.getKey() + lastEntry.getValue();
                if (mmapAddress + length <= entry.getKey()) {
                    return mmapAddress;
                } else {
                    lastEntry = entry;
                }
            }
        }
        if (lastEntry != null) {
            long mmapAddress = lastEntry.getKey() + lastEntry.getValue();
            if (mmapAddress < mmapBaseAddress) {
                log.debug("allocateMapAddress mmapBaseAddress=0x" + Long.toHexString(mmapBaseAddress) + ", mmapAddress=0x" + Long.toHexString(mmapAddress));
                mmapBaseAddress = mmapAddress;
            }
        }

        long addr = mmapBaseAddress;
        mmapBaseAddress += length;
        return addr;
    }

    @Override
    public MemoryBlock malloc(int length) {
        return malloc(length, true);
    }

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        if (runtime) {
            return MemoryBlockImpl.alloc(this, length);
        }

        long address = malloc.call(emulator, length)[0].intValue() & 0xffffffffL;
        final UnicornPointer pointer = UnicornPointer.pointer(emulator, address);
        assert pointer != null;
        return new MemoryBlock() {
            @Override
            public UnicornPointer getPointer() {
                return pointer;
            }
            @Override
            public boolean isSame(Pointer p) {
                return pointer.equals(p);
            }
            @Override
            public void free() {
                throw new UnsupportedOperationException();
            }
        };
    }

    @Override
    public UnicornPointer mmap(int length, int prot) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());
        UnicornPointer pointer = UnicornPointer.pointer(emulator, mmap2(0, aligned, prot, 0, -1, 0) & 0xffffffffL);
        assert pointer != null;
        return pointer.setSize(aligned);
    }

    private static final int MAP_ANONYMOUS = 0x20;

    @Override
    public int mmap2(long start, int length, int prot, int flags, int fd, int offset) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());

        if (((flags & MAP_ANONYMOUS) != 0) || (start == 0 && fd == -1 && offset == 0)) {
            long addr = allocateMapAddress(aligned);
            log.debug("mmap2 addr=0x" + Long.toHexString(addr) + ", mmapBaseAddress=0x" + Long.toHexString(mmapBaseAddress) + ", start=" + start + ", fd=" + fd + ", offset=" + offset + ", aligned=" + aligned);
            unicorn.mem_map(addr, aligned, prot);
            memoryMap.put(addr, aligned);
            return (int) addr;
        }
        try {
            FileIO file;
            if (start == 0 && fd >= 0 && (file = syscallHandler.fdMap.get(fd)) != null) {
                long addr = allocateMapAddress(aligned);
                log.debug("mmap2 addr=0x" + Long.toHexString(addr) + ", mmapBaseAddress=0x" + Long.toHexString(mmapBaseAddress));
                return file.mmap2(unicorn, addr, aligned, prot, offset, length, memoryMap);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        throw new AbstractMethodError("mmap2 start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset);
    }

    @Override
    public int munmap(long start, int length) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());
        unicorn.mem_unmap(start, aligned);
        Integer removed = memoryMap.remove(start);

        if (removed == null) {
            Map.Entry<Long, Integer> segment = null;
            for (Map.Entry<Long, Integer> entry : memoryMap.entrySet()) {
                if (start > entry.getKey() && start < entry.getKey() + entry.getValue()) {
                    segment = entry;
                    break;
                }
            }
            if (segment == null || segment.getValue() < aligned) {
                throw new IllegalStateException("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start));
            }

            memoryMap.put(segment.getKey(), (int) (start - segment.getKey()));
            log.debug("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start) + ", base=0x" + Long.toHexString(segment.getKey()) + ", size=" + (start - segment.getKey()));
            if (start + aligned < segment.getKey() + segment.getValue()) {
                log.debug("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start) + ", base=0x" + Long.toHexString(start + aligned) + ", size=" + (segment.getKey() + segment.getValue() - start - aligned));
                memoryMap.put(start + aligned, (int) (segment.getKey() + segment.getValue() - start - aligned));
            }

            return 0;
        }

        if(removed != aligned) {
            if (aligned >= removed) {
                throw new IllegalStateException("munmap removed=0x" + Long.toHexString(removed) + ", aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start));
            }

            memoryMap.put(start + aligned, removed - aligned);
            log.debug("munmap removed=0x" + Long.toHexString(removed) + ", aligned=0x" + Long.toHexString(aligned) + ", base=0x" + Long.toHexString(start + aligned) + ", size=" + (removed - aligned));
            return 0;
        }
        return 0;
    }

    @Override
    public int mprotect(long address, int length, int prot) {
        if (address % ARMEmulator.PAGE_ALIGN != 0) {
            setErrno(LinuxEmulator.EINVAL);
            return -1;
        }

        unicorn.mem_protect(address, length, prot);
        return 0;
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
        return modules.values();
    }

    private final List<HookListener> hookListeners = new ArrayList<>();

    @Override
    public void addHookListener(HookListener listener) {
        hookListeners.add(listener);
    }
}
