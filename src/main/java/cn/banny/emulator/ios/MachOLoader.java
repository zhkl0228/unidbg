package cn.banny.emulator.ios;

import cn.banny.emulator.*;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.pointer.UnicornPointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;
import unicorn.UnicornConst;
import unicorn.WriteHook;

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
        this.setErrno(0);
    }

    @Override
    protected Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook, boolean forceCallInit) throws IOException {
        return loadInternalPhase(libraryFile, unpackHook, true);
    }

    private MachOModule loadInternalPhase(LibraryFile libraryFile, WriteHook unpackHook, boolean loadNeeded) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(libraryFile.readToByteArray());
        return loadInternal(libraryFile, unpackHook, buffer, loadNeeded);
    }

    private MachOModule loadInternal(LibraryFile libraryFile, final WriteHook unpackHook, ByteBuffer buffer, boolean loadNeeded) throws IOException {
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
                MachO.FatArch arch = archMap.get(CPU_SUBTYPE_ARM_V7); // 优化加载armv7
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
                    return loadInternal(libraryFile, unpackHook, buffer.slice(), loadNeeded);
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
        long bound_high = 0;
        String dyId = libraryFile.getName();
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
                    long high = segmentCommand.vmaddr() + segmentCommand.vmsize();
                    if (bound_high < high) {
                        bound_high = high;
                    }
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if ("__PAGEZERO".equals(segmentCommand64.segname())) {
                        break;
                    }
                    high = segmentCommand64.vmaddr() + segmentCommand64.vmsize();
                    if (bound_high < high) {
                        bound_high = high;
                    }
                    break;
                case ID_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    String dylib = dylibCommand.name();
                    dyId = FilenameUtils.getName(dylib);
                    break;
                case LOAD_DYLIB:
                case LOAD_UPWARD_DYLIB:
                case SYMTAB:
                case REEXPORT_DYLIB:
                case DYSYMTAB:
                    break;
                case ENCRYPTION_INFO:
                case ENCRYPTION_INFO_64:
                    throw new UnsupportedOperationException("Encrypted file");
                default:
                    log.debug("loadCommand=" + command.type());
                    break;
            }
        }

        final long baseAlign = emulator.getPageAlign();
        final long load_base = ((mmapBaseAddress - 1) / baseAlign + 1) * baseAlign;
        long size = emulator.align(0, bound_high).size;
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
                    if ("__PAGEZERO".equals(segmentCommand.segname())) {
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
                    if ("__PAGEZERO".equals(segmentCommand64.segname())) {
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
        if (log.isDebugEnabled()) {
            log.debug("load dyId=" + dyId + ", base=0x" + Long.toHexString(load_base) + ", compressed=" + compressed + ", loadNeeded=" + loadNeeded + ", regions=" + regions);
        }

        Map<String, MachOModule> neededLibraries = new HashMap<>();
        for (MachO.DylibCommand dylibCommand : exportDylibs) {
            String neededLibrary = dylibCommand.name();
            log.debug(dyId + " need export dependency " + neededLibrary);

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
                MachOModule needed = loadInternalPhase(neededLibraryFile, null, false);
                needed.addReferenceCount();
                neededLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
            } else {
                log.debug(dyId + " load export dependency " + neededLibrary + " failed");
            }
        }
        for (MachOModule export : neededLibraries.values()) {
            for (Iterator<NeedLibrary> iterator = export.lazyLoadNeededList.iterator(); iterator.hasNext(); ) {
                NeedLibrary library = iterator.next();
                String neededLibrary = library.path;
                iterator.remove();

                String name = FilenameUtils.getName(neededLibrary);
                MachOModule loaded = modules.get(name);
                if (loaded != null) {
                    if (library.upward) {
                        export.upwardLibraries.put(name, loaded);
                    } else {
                        export.neededLibraries().put(name, loaded);
                    }
                }
            }

            bindIndirectSymbolPointers(export);
        }

        Map<String, Module> upwardLibraries = new HashMap<>();
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
                    MachOModule needed = loadInternalPhase(neededLibraryFile, null, loadNeeded);
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
        long load_size = bound_high;
        MachOModule module = new MachOModule(machO, dyId, load_base, load_size, new HashMap<String, Module>(neededLibraries), regions,
                symtabCommand, dysymtabCommand, buffer, lazyLoadNeededList, upwardLibraries);

        if (loadNeeded) {
            if (log.isDebugEnabled()) {
                log.debug("Begin bind dyId=" + dyId + ", base=0x" + Long.toHexString(load_base));
            }
            bindIndirectSymbolPointers(module);
        }

        modules.put(dyId, module);
        if (maxDylibName == null || dyId.length() > maxDylibName.length()) {
            maxDylibName = dyId;
        }
        if (bound_high > maxSizeOfDylib) {
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
        if (dysymtabCommand == null) {
            return;
        }
        List<Long> indirectTable = dysymtabCommand.indirectSymbols();

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
                                continue;
                            }

                            MachOSymbol sym = module.getSymbolByIndex((int) symbolIndex);
                            if (sym == null) {
                                log.warn("bindIndirectSymbolPointers sym is null");
                                continue;
                            }

                            Symbol replace = module.findSymbolByName(sym.getName(), false);
                            if (replace == null) {
                                for (Module needed : module.getNeededLibraries()) {
                                    replace = needed.findSymbolByName(sym.getName(), true);
                                    if (replace != null) {
                                        break;
                                    }
                                }
                            }
                            if (replace == null) {
                                for (Module needed : module.upwardLibraries.values()) {
                                    replace = needed.findSymbolByName(sym.getName(), false);
                                    if (replace != null) {
                                        break;
                                    }
                                }
                            }
                            if (replace == null) {
                                log.warn("bindIndirectSymbolPointers failed symbolIndex=0x" + Long.toHexString(symbolIndex) + ", name=" + module.name + ", sym=" + sym + ", ptrToBind=0x" + Long.toHexString(ptrToBind));
                            } else {
                                UnicornPointer pointer = UnicornPointer.pointer(emulator, ptrToBind + module.base);
                                if (pointer == null) {
                                    throw new IllegalStateException("pointer=" + pointer);
                                }
                                if (emulator.getPointerSize() == 4) {
                                    pointer.setInt(0, (int) replace.getAddress());
                                } else if(emulator.getPointerSize() == 8) {
                                    pointer.setLong(0, replace.getAddress());
                                } else {
                                    throw new IllegalStateException();
                                }
                                log.debug("bindIndirectSymbolPointers symbolIndex=0x" + Long.toHexString(symbolIndex) + ", sym=" + sym + ", ptrToBind=0x" + Long.toHexString(ptrToBind) + ", replace0x=" + Long.toHexString(replace.getAddress()));
                            }
                        }
                    }
                    break;
                case SEGMENT_64:
                    throw new UnsupportedOperationException("bindIndirectSymbolPointers");
            }
        }
    }

    private String maxDylibName;
    private long maxSizeOfDylib;

    private void write_mem(int offset, int size, long begin, ByteBuffer buffer) {
        if (size > 0) {
            buffer.limit(offset + size);
            buffer.position(offset);
            byte[] loadData = new byte[size];
            buffer.get(loadData);
            unicorn.mem_write(begin, loadData);
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
    public int mmap2(long start, int length, int prot, int flags, int fd, int offset) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int brk(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setErrno(int errno) {
    }

    @Override
    public File dumpHeap() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] unpack(File elfFile) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module dlopen(String filename) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module dlopen(String filename, boolean calInit) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean dlclose(long handle) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Symbol dlsym(long handle, String symbol) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Collection<Module> getLoadedModules() {
        return new HashSet<Module>(modules.values());
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
