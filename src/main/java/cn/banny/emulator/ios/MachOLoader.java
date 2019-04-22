package cn.banny.emulator.ios;

import cn.banny.emulator.*;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
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
    }

    @Override
    protected Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook, boolean forceCallInit) throws IOException {
        return loadInternal(libraryFile, unpackHook);
    }

    private Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(libraryFile.readToByteArray());
        return loadInternal(libraryFile, unpackHook, buffer);
    }

    private Module loadInternal(LibraryFile libraryFile, final WriteHook unpackHook, ByteBuffer buffer) throws IOException {
        MachO machO = new MachO(new ByteBufferKaitaiStream(buffer));
        MachO.MagicType magic = machO.magic();
        switch (magic) {
            case FAT_BE:
                for (MachO.FatArch arch : machO.fatHeader().fatArchs()) {
                    if ((arch.cputype() == MachO.CpuType.ARM && emulator.getPointerSize() == 4) || (arch.cputype() == MachO.CpuType.ARM64 && emulator.getPointerSize() == 8)) {
                        buffer.limit((int) (arch.offset() + arch.size()));
                        buffer.position((int) arch.offset());
                        log.debug("loadFatArch=" + arch.cputype() + ", cpuSubType=" + arch.cpusubtype());
                        return loadInternal(libraryFile, unpackHook, buffer.slice());
                    }
                }
                throw new UnsupportedOperationException("find arch failed");
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
                throw new UnsupportedOperationException("magic=" + machO);
        }

        switch (machO.header().filetype()) {
            case DYLIB:
            case EXECUTE:
                break;
            default:
                throw new UnsupportedOperationException("fileType=" + machO.header().filetype());
        }

        long bound_low = 0;
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
                    if (bound_low > segmentCommand.vmaddr()) {
                        bound_low = segmentCommand.vmaddr();
                    }
                    long high = segmentCommand.vmaddr() + segmentCommand.vmsize();
                    if (bound_high < high) {
                        bound_high = high;
                    }
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if (bound_low > segmentCommand64.vmaddr()) {
                        bound_low = segmentCommand64.vmaddr();
                    }
                    high = segmentCommand64.vmaddr() + segmentCommand64.vmsize();
                    if (bound_high < high) {
                        bound_high = high;
                    }
                    break;
                case ID_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    dyId = dylibCommand.name();
                    break;
                case LOAD_DYLIB:
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
        long size = emulator.align(0, bound_high - bound_low).size;
        mmapBaseAddress = load_base + size;

        final List<String> neededList = new ArrayList<>();
        final List<MemRegion> regions = new ArrayList<>(5);
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
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
                    neededList.add(dylibCommand.name());
                    break;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("load dyId=" + dyId + ", bound_low=0x" + Long.toHexString(bound_low) + ", bound_high=0x" + Long.toHexString(bound_high) + ", compressed=" + compressed + ", regions=" + regions);
        }

        Map<String, Module> neededLibraries = new HashMap<>();
        for (String neededLibrary : neededList) {
            log.debug(dyId + " need dependency " + neededLibrary);

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
                log.info(dyId + " load dependency " + neededLibrary + " failed");
            }
        }

        throw new UnsupportedOperationException();
    }

    private void write_mem(int offset, int size, long begin, ByteBuffer buffer) {
        if (size > 0) {
            buffer.limit(offset + size);
            buffer.position(offset);
            byte[] loadData = new byte[size];
            buffer.get(loadData);
            unicorn.mem_write(begin, loadData);
        }
    }

    private final Map<String, Module> modules = new LinkedHashMap<>();

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
    public Module findModuleByAddress(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module findModule(String soName) {
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
        throw new UnsupportedOperationException();
    }

    @Override
    public String getMaxLengthLibraryName() {
        throw new UnsupportedOperationException();
    }

    @Override
    public long getMaxSizeOfLibrary() {
        throw new UnsupportedOperationException();
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
