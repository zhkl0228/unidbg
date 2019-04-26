package cn.banny.emulator.ios;

import cn.banny.emulator.*;
import cn.banny.emulator.hook.HookListener;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.memory.MemoryBlockImpl;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.AbstractLoader;
import cn.banny.emulator.spi.LibraryFile;
import cn.banny.emulator.spi.Loader;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.*;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

public class MachOLoader extends AbstractLoader implements Memory, Loader, cn.banny.emulator.ios.MachO {

    private static final Log log = LogFactory.getLog(MachOLoader.class);

    MachOLoader(Emulator emulator, AbstractSyscallHandler syscallHandler) {
        super(emulator, syscallHandler);

        // init stack
        final long stackSize = STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        unicorn.mem_map(STACK_BASE - stackSize, stackSize, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

        setStackPoint(STACK_BASE);
        initializeTLS();
        this.setErrno(0);
    }

    private void initializeTLS() {
        final UnicornPointer tls = allocateStack(0x80 * 4); // tls size
        assert tls != null;

        if (emulator.getPointerSize() == 4) {
            unicorn.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tls.peer);
        } else {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, tls.peer);
        }
        log.debug("initializeTLS tls=" + tls);
    }

    @Override
    protected Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook, boolean forceCallInit) throws IOException {
        Module module = loadInternalPhase(libraryFile, true);
        for (MachOModule export : modules.values()) {
            if (!export.lazyLoadNeededList.isEmpty()) {
                log.info("Export module resolve needed library failed: " + export.name + ", neededList=" + export.lazyLoadNeededList);
            }
        }
        for (MachOModule m : modules.values()) {
            bindIndirectSymbolPointers(m);
        }
        if (callInitFunction) {
            for (MachOModule m : modules.values()) {
                m.callInitFunction(emulator);
            }
        }

        return module;
    }

    private MachOModule loadInternalPhase(LibraryFile libraryFile, boolean loadNeeded) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(libraryFile.readToByteArray());
        return loadInternalPhase(libraryFile, buffer, loadNeeded);
    }

    private MachOModule loadInternalPhase(LibraryFile libraryFile, ByteBuffer buffer, boolean loadNeeded) throws IOException {
        MachO machO = new MachO(new ByteBufferKaitaiStream(buffer));
        MachO.MagicType magic = machO.magic();
        switch (magic) {
            case FAT_BE:
                Map<Long, MachO.FatArch> archMap = new HashMap<>();
                for (MachO.FatArch arch : machO.fatHeader().fatArchs()) {
                    if ((arch.cputype() == MachO.CpuType.ARM && emulator.getPointerSize() == 4) || (arch.cputype() == MachO.CpuType.ARM64 && emulator.getPointerSize() == 8)) {
                        archMap.put(arch.cpusubtype(), arch);
                    }
                }
                MachO.FatArch arch = archMap.get(CPU_SUBTYPE_ARM_V7); // 优先加载armv7
                if (arch == null) {
                    Iterator<MachO.FatArch> iterator = archMap.values().iterator();
                    if (iterator.hasNext()) {
                        arch = iterator.next();
                    }
                }
                if (arch != null) {
                    buffer.limit((int) (arch.offset() + arch.size()));
                    buffer.position((int) arch.offset());
                    log.debug("loadFatArch=" + arch.cputype() + ", cpuSubType=" + arch.cpusubtype());
                    return loadInternalPhase(libraryFile, buffer.slice(), loadNeeded);
                }
                throw new IllegalArgumentException("find arch failed");
            case MACHO_LE_X86: // ARM
                if (machO.header().cputype() != MachO.CpuType.ARM) {
                    throw new UnsupportedOperationException("cpuType=" + machO.header().cputype());
                }
                break;
            case MACHO_LE_X64:
                if (machO.header().cputype() != MachO.CpuType.ARM64) {
                    throw new UnsupportedOperationException("cpuType=" + machO.header().cputype());
                }
                break;
            default:
                throw new UnsupportedOperationException("magic=" + magic);
        }

        switch (machO.header().filetype()) {
            case DYLIB:
            case EXECUTE:
                break;
            default:
                throw new UnsupportedOperationException("fileType=" + machO.header().filetype());
        }

        long start = System.currentTimeMillis();
        long size = 0;
        String dyId = libraryFile.getName();
        String dylibPath = libraryFile.getName();
        boolean compressed = false;
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case DYLD_INFO:
                case DYLD_INFO_ONLY:
                    compressed = true;
                    break;
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    if ("__PAGEZERO".equals(segmentCommand.segname())) {
                        break;
                    }
                    if (segmentCommand.filesize() > segmentCommand.vmsize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment load command %s filesize is larger than vmsize", command.type()));
                    }
                    if(segmentCommand.vmaddr() % emulator.getPageAlign() != 0 || (segmentCommand.vmaddr() + segmentCommand.vmsize()) % emulator.getPageAlign() != 0) {
                        throw new IllegalArgumentException("vmaddr not page aligned");
                    }

                    if (segmentCommand.vmsize() == 0) {
                        break;
                    }
                    if (segmentCommand.vmsize() < segmentCommand.filesize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment %s has vmsize < filesize", command.type()));
                    }
                    long high = segmentCommand.vmaddr() + segmentCommand.vmsize();
                    if (size < high) {
                        size = high;
                    }
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if ("__PAGEZERO".equals(segmentCommand64.segname())) {
                        break;
                    }
                    if (segmentCommand64.filesize() > segmentCommand64.vmsize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment load command %s filesize is larger than vmsize", command.type()));
                    }
                    if(segmentCommand64.vmaddr() % emulator.getPageAlign() != 0 || (segmentCommand64.vmaddr() + segmentCommand64.vmsize()) % emulator.getPageAlign() != 0) {
                        throw new IllegalArgumentException("vmaddr or vmsize not page aligned");
                    }

                    if (segmentCommand64.vmsize() == 0) {
                        break;
                    }
                    if (segmentCommand64.vmsize() < segmentCommand64.filesize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment %s has vmsize < filesize", command.type()));
                    }
                    high = segmentCommand64.vmaddr() + segmentCommand64.vmsize();
                    if (size < high) {
                        size = high;
                    }
                    break;
                case ID_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    dylibPath = dylibCommand.name().replace("@rpath", libraryFile.getPath());
                    dyId = FilenameUtils.getName(dylibPath);
                    break;
                case LOAD_DYLIB:
                // case LOAD_WEAK_DYLIB:
                case REEXPORT_DYLIB:
                case LOAD_UPWARD_DYLIB:
                case SYMTAB:
                case DYSYMTAB:
                    break;
                case ENCRYPTION_INFO:
                case ENCRYPTION_INFO_64:
                    MachO.EncryptionInfoCommand encryptionInfoCommand = (MachO.EncryptionInfoCommand) command.body();
                    if (encryptionInfoCommand.cryptid() != 0) {
                        throw new UnsupportedOperationException("Encrypted file");
                    }
                    break;
                case UUID:
                case VERSION_MIN_IPHONEOS:
                case FUNCTION_STARTS:
                case DATA_IN_CODE:
                case CODE_SIGNATURE:
                case SOURCE_VERSION:
                case SEGMENT_SPLIT_INFO:
                case DYLIB_CODE_SIGN_DRS:
                case SUB_FRAMEWORK:
                case RPATH:
                    break;
                default:
                    log.info("Not handle loadCommand=" + command.type() + ", dylibPath=" + dylibPath);
                    break;
            }
        }

        final long load_base = mmapBaseAddress;
        mmapBaseAddress = load_base + size;

        final List<NeedLibrary> neededList = new ArrayList<>();
        final List<MemRegion> regions = new ArrayList<>(5);
        final List<MachO.DylibCommand> exportDylibs = new ArrayList<>();
        MachO.SymtabCommand symtabCommand = null;
        MachO.DysymtabCommand dysymtabCommand = null;
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    if (segmentCommand.vmsize() == 0) {
                        break;
                    }
                    int prot = get_segment_protection(segmentCommand.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    long begin = load_base + segmentCommand.vmaddr();
                    Alignment alignment = this.mem_map(begin, segmentCommand.vmsize(), prot, dyId);
                    write_mem((int) segmentCommand.fileoff(), (int) segmentCommand.filesize(), begin, buffer);

                    regions.add(new MemRegion(alignment.address, alignment.address + alignment.size, prot, libraryFile, segmentCommand.vmaddr()));
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if (segmentCommand64.vmsize() == 0) {
                        break;
                    }
                    prot = get_segment_protection(segmentCommand64.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    begin = load_base + segmentCommand64.vmaddr();
                    alignment = this.mem_map(begin, segmentCommand64.vmsize(), prot, dyId);
                    write_mem((int) segmentCommand64.fileoff(), (int) segmentCommand64.filesize(), begin, buffer);

                    regions.add(new MemRegion(alignment.address, alignment.address + alignment.size, prot, libraryFile, segmentCommand64.vmaddr()));
                    break;
                case LOAD_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    neededList.add(new NeedLibrary(dylibCommand.name(), false));
                    break;
                case LOAD_UPWARD_DYLIB:
                    dylibCommand = (MachO.DylibCommand) command.body();
                    neededList.add(new NeedLibrary(dylibCommand.name(), true));
                    break;
                case SYMTAB:
                    symtabCommand = (MachO.SymtabCommand) command.body();
                    break;
                case DYSYMTAB:
                    dysymtabCommand = (MachO.DysymtabCommand) command.body();
                    break;
                case REEXPORT_DYLIB:
                    exportDylibs.add((MachO.DylibCommand) command.body());
                    break;
            }
        }
        Log log = LogFactory.getLog("cn.banny.emulator.ios." + dyId);
        if (log.isDebugEnabled()) {
            log.debug("load dyId=" + dyId + ", base=0x" + Long.toHexString(load_base) + ", compressed=" + compressed + ", loadNeeded=" + loadNeeded + ", regions=" + regions);
        }

        Map<String, MachOModule> exportModules = new LinkedHashMap<>();
        for (MachO.DylibCommand dylibCommand : exportDylibs) {
            String neededLibrary = dylibCommand.name();
            log.debug(dyId + " need export dependency " + neededLibrary);

            MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
            if (loaded != null) {
                loaded.addReferenceCount();
                exportModules.put(FilenameUtils.getBaseName(loaded.name), loaded);
                continue;
            }
            LibraryFile neededLibraryFile = libraryFile.resolveLibrary(emulator, neededLibrary);
            if (libraryResolver != null && neededLibraryFile == null) {
                neededLibraryFile = libraryResolver.resolveLibrary(emulator, neededLibrary);
            }
            if (neededLibraryFile != null) {
                MachOModule needed = loadInternalPhase(neededLibraryFile, false);
                needed.addReferenceCount();
                exportModules.put(FilenameUtils.getBaseName(needed.name), needed);
            } else {
                log.debug(dyId + " load export dependency " + neededLibrary + " failed");
            }
        }

        Map<String, MachOModule> neededLibraries = new LinkedHashMap<>();
        Map<String, Module> upwardLibraries = new LinkedHashMap<>();
        final List<NeedLibrary> lazyLoadNeededList;
        if (loadNeeded) {
            lazyLoadNeededList = Collections.emptyList();
            for (NeedLibrary library : neededList) {
                String neededLibrary = library.path;
                log.debug(dyId + " need dependency " + neededLibrary);

                MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
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
                    MachOModule needed = loadInternalPhase(neededLibraryFile, loadNeeded);
                    needed.addReferenceCount();
                    if (library.upward) {
                        upwardLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
                    } else {
                        neededLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
                    }
                } else {
                    log.info(dyId + " load dependency " + neededLibrary + " failed");
                }
            }
        } else {
            lazyLoadNeededList = neededList;
        }

        if (log.isDebugEnabled()) {
            log.debug("load dyId=" + dyId + ", base=0x" + Long.toHexString(load_base) + ", neededLibraries=" + neededLibraries + ", upwardLibraries=" + upwardLibraries);
        }
        long load_size = size;
        MachOModule module = new MachOModule(machO, dyId, load_base, load_size, new HashMap<String, Module>(neededLibraries), regions,
                symtabCommand, dysymtabCommand, buffer, lazyLoadNeededList, upwardLibraries, exportModules, dylibPath, emulator);
        modules.put(dyId, module);

        for (MachOModule export : modules.values()) {
            for (Iterator<NeedLibrary> iterator = export.lazyLoadNeededList.iterator(); iterator.hasNext(); ) {
                NeedLibrary library = iterator.next();
                String neededLibrary = library.path;

                String name = FilenameUtils.getName(neededLibrary);
                MachOModule loaded = modules.get(name);
                if (loaded != null) {
                    if (library.upward) {
                        export.upwardLibraries.put(name, loaded);
                    } else {
                        export.neededLibraries().put(name, loaded);
                    }
                    iterator.remove();
                }
            }
        }

        if (maxDylibName == null || dyId.length() > maxDylibName.length()) {
            maxDylibName = dyId;
        }
        if (size > maxSizeOfDylib) {
            maxSizeOfDylib = load_size;
        }

        log.debug("Load library " + dyId + " offset=" + (System.currentTimeMillis() - start) + "ms");
        if (moduleListener != null) {
            moduleListener.onLoaded(emulator, module);
        }

        return module;
    }

    private void bindIndirectSymbolPointers(MachOModule module) throws IOException {
        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (dysymtabCommand == null || module.indirectSymbolBound) {
            return;
        }
        module.indirectSymbolBound = true;
        List<Long> indirectTable = dysymtabCommand.indirectSymbols();
        Log log = LogFactory.getLog("cn.banny.emulator.ios." + module.name);

        for (MachO.LoadCommand command : module.machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                        long type = section.flags() & SECTION_TYPE;
                        long elementCount = section.size() / emulator.getPointerSize();

                        if (type != S_NON_LAZY_SYMBOL_POINTERS && type != S_LAZY_SYMBOL_POINTERS) {
                            continue;
                        }

                        long ptrToBind = section.addr();
                        int indirectTableOffset = (int) section.reserved1();
                        for (int i = 0; i < elementCount; i++, ptrToBind += emulator.getPointerSize()) {
                            long symbolIndex = indirectTable.get(indirectTableOffset + i);
                            if (symbolIndex == INDIRECT_SYMBOL_ABS) {
                                continue; // do nothing since already has absolute address
                            }
                            if (symbolIndex == INDIRECT_SYMBOL_LOCAL) {
                                UnicornPointer pointer = UnicornPointer.pointer(emulator, ptrToBind + module.base);
                                if (pointer == null) {
                                    throw new IllegalStateException("pointer=" + pointer);
                                }
                                Pointer newPointer = pointer.getPointer(0);
                                if (newPointer == null) {
                                    newPointer = UnicornPointer.pointer(emulator, module.base);
                                } else {
                                    newPointer = newPointer.share(module.base);
                                }
                                pointer.setPointer(0, newPointer);
                                continue;
                            }

                            MachOSymbol sym = module.getSymbolByIndex((int) symbolIndex);
                            if (sym == null) {
                                log.warn("bindIndirectSymbolPointers sym is null");
                                continue;
                            }

                            boolean isWeakRef = (sym.nlist.desc() & N_WEAK_REF) != 0;
                            Symbol replace = module.findSymbolByName(sym.getName(), true);
                            long address = replace == null ? 0L : replace.getAddress();
                            for (HookListener listener : hookListeners) {
                                long hook = listener.hook(emulator.getSvcMemory(), replace == null ? module.name : replace.getModuleName(), sym.getName(), address);
                                if (hook > 0) {
                                    address = hook;
                                    break;
                                }
                            }

                            UnicornPointer pointer = UnicornPointer.pointer(emulator, ptrToBind + module.base);
                            if (pointer == null) {
                                throw new IllegalStateException("pointer=" + pointer);
                            }
                            if (address == 0L) {
                                if (isWeakRef) {
                                    log.info("bindIndirectSymbolPointers sym=" + sym + ", isWeakRef=" + isWeakRef);
                                    pointer.setPointer(0, null);
                                } else {
                                    log.warn("bindIndirectSymbolPointers failed sym=" + sym);
                                }
                            } else {
                                pointer.setPointer(0, UnicornPointer.pointer(emulator, address));
                                log.debug("bindIndirectSymbolPointers symbolIndex=0x" + Long.toHexString(symbolIndex) + ", sym=" + sym + ", ptrToBind=0x" + Long.toHexString(ptrToBind) + ", replace0x=" + Long.toHexString(replace.getAddress()));
                            }
                        }
                    }
                    break;
                case SEGMENT_64:
                    throw new UnsupportedOperationException("bindIndirectSymbolPointers SEGMENT_64");
            }
        }
    }

    private String maxDylibName;
    private long maxSizeOfDylib;

    private void write_mem(int offset, int size, long begin, ByteBuffer buffer) {
        if (size > 0) {
            buffer.limit(offset + size);
            buffer.position(offset);
            byte[] data = new byte[size];
            buffer.get(data);
            unicorn.mem_write(begin, data);
        }
    }

    private final Map<String, MachOModule> modules = new LinkedHashMap<>();

    private int get_segment_protection(MachO.VmProt vmProt) {
        int prot = Unicorn.UC_PROT_NONE;
        if (vmProt.read()) prot |= Unicorn.UC_PROT_READ;
        if (vmProt.write()) prot |= Unicorn.UC_PROT_WRITE;
        if (vmProt.execute()) prot |= Unicorn.UC_PROT_EXEC;
        return prot;
    }

    @Override
    public int brk(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        if (runtime) {
            return MemoryBlockImpl.alloc(this, length);
        }

        throw new UnsupportedOperationException();
    }

    @Override
    public void setErrno(int errno) {
    }

    @Override
    public File dumpHeap() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] unpack(File elfFile) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module dlopen(String filename) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module dlopen(String filename, boolean calInit) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean dlclose(long handle) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Symbol dlsym(long handle, String symbol) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Collection<Module> getLoadedModules() {
        return new ArrayList<Module>(modules.values());
    }

    @Override
    public String getMaxLengthLibraryName() {
        return maxDylibName;
    }

    @Override
    public long getMaxSizeOfLibrary() {
        return maxSizeOfDylib;
    }

    @Override
    public void runThread(int threadId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void runLastThread() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean hasThread(int threadId) {
        throw new UnsupportedOperationException();
    }

}
