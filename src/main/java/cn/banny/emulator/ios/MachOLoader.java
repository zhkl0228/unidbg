package cn.banny.emulator.ios;

import cn.banny.emulator.*;
import cn.banny.emulator.hook.HookListener;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.memory.*;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.AbstractLoader;
import cn.banny.emulator.spi.LibraryFile;
import cn.banny.emulator.spi.Loader;
import cn.banny.emulator.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class MachOLoader extends AbstractLoader implements Memory, Loader, cn.banny.emulator.ios.MachO {

    private static final Log log = LogFactory.getLog(MachOLoader.class);

    MachOLoader(Emulator emulator, UnixSyscallHandler syscallHandler) {
        super(emulator, syscallHandler);

        // init stack
        final long stackSize = STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        unicorn.mem_map(STACK_BASE - stackSize, stackSize, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

        setStackPoint(STACK_BASE);
        initializeTLS();
        this.setErrno(0);
    }

    private UnicornPointer vars;

    private void initializeTLS() {
        vars = allocateStack(emulator.getPointerSize() * 5);

        final Pointer thread = allocateStack(0x400); // reserve space for pthread_internal_t

        final UnicornPointer tls = allocateStack(0x80 * 4); // tls size
        assert tls != null;
        tls.setPointer(0, thread);

        if (emulator.getPointerSize() == 4) {
            unicorn.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tls.peer);
        } else {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, tls.peer);
        }
        log.debug("initializeTLS tls=" + tls + ", thread=" + thread);
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

    MachO.VersionMinCommand sdkVersion;

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
        MachO.DyldInfoCommand dyldInfoCommand = null;
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case DYLD_INFO:
                case DYLD_INFO_ONLY:
                    if (dyldInfoCommand != null) {
                        throw new IllegalStateException("dyldInfoCommand=" + dyldInfoCommand);
                    }
                    dyldInfoCommand = (MachO.DyldInfoCommand) command.body();
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
                case FUNCTION_STARTS:
                case DATA_IN_CODE:
                case CODE_SIGNATURE:
                case SOURCE_VERSION:
                case SEGMENT_SPLIT_INFO:
                case DYLIB_CODE_SIGN_DRS:
                case SUB_FRAMEWORK:
                case RPATH:
                case VERSION_MIN_IPHONEOS:
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
                    long begin = load_base + segmentCommand.vmaddr();
                    if (segmentCommand.vmsize() == 0) {
                        regions.add(new MemRegion(begin, begin, 0, libraryFile, segmentCommand.vmaddr()));
                        break;
                    }
                    int prot = get_segment_protection(segmentCommand.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    Alignment alignment = this.mem_map(begin, segmentCommand.vmsize(), prot, dyId);
                    write_mem((int) segmentCommand.fileoff(), (int) segmentCommand.filesize(), begin, buffer);

                    regions.add(new MemRegion(alignment.address, alignment.address + alignment.size, prot, libraryFile, segmentCommand.vmaddr()));
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    begin = load_base + segmentCommand64.vmaddr();
                    if (segmentCommand64.vmsize() == 0) {
                        regions.add(new MemRegion(begin, begin, 0, libraryFile, segmentCommand64.vmaddr()));
                        break;
                    }
                    prot = get_segment_protection(segmentCommand64.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

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
                case VERSION_MIN_IPHONEOS:
                    if ("libSystem.B.dylib".equals(dyId)) {
                        sdkVersion = (MachO.VersionMinCommand) command.body();
                    }
                    break;
            }
        }
        Log log = LogFactory.getLog("cn.banny.emulator.ios." + dyId);
        if (log.isDebugEnabled() || MachOLoader.log.isDebugEnabled()) {
            String msg = "load dyId=" + dyId + ", base=0x" + Long.toHexString(load_base) + ", dyldInfoCommand=" + dyldInfoCommand + ", loadNeeded=" + loadNeeded + ", regions=" + regions;
            if (log.isDebugEnabled()) {
                log.debug(msg);
            } else {
                MachOLoader.log.debug(msg);
            }
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

        if (log.isDebugEnabled() || MachOLoader.log.isDebugEnabled()) {
            String msg = "load dyId=" + dyId + ", base=0x" + Long.toHexString(load_base) + ", neededLibraries=" + neededLibraries + ", upwardLibraries=" + upwardLibraries;
            if (log.isDebugEnabled()) {
                log.debug(msg);
            } else {
                MachOLoader.log.debug(msg);
            }
        }
        long load_size = size;
        MachOModule module = new MachOModule(machO, dyId, load_base, load_size, new HashMap<String, Module>(neededLibraries), regions,
                symtabCommand, dysymtabCommand, buffer, lazyLoadNeededList, upwardLibraries, exportModules, dylibPath, emulator, dyldInfoCommand, null, null, vars);
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

        processDyldInfo(module);

        if ("libsystem_malloc.dylib".equals(dyId)) {
            malloc = module.findSymbolByName("_malloc");
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

    private void processExportNode(Log log, ByteBuffer buffer, byte[] cummulativeString, int curStrOffset) {
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
            if (log.isDebugEnabled()) {
                String symbolName = new String(cummulativeString, 0, curStrOffset);
                log.debug("exportNode symbolName=" + symbolName + ", address=0x" + Long.toHexString(address) + ", other=0x" + Long.toHexString(other) + ", importName=" + importName);
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
            processExportNode(log, duplicate, cummulativeString, curStrOffset+edgeStrLen);
        }
    }

    private void processDyldInfo(MachOModule module) {
        MachO.DyldInfoCommand dyldInfoCommand = module.dyldInfoCommand;
        if (dyldInfoCommand == null) {
            return;
        }

        Log log = LogFactory.getLog("cn.banny.emulator.ios." + module.name);

        if (dyldInfoCommand.rebaseSize() > 0) {
            ByteBuffer buffer = module.buffer.duplicate();
            buffer.limit((int) (dyldInfoCommand.rebaseOff() + dyldInfoCommand.rebaseSize()));
            buffer.position((int) dyldInfoCommand.rebaseOff());
            rebase(log, buffer.slice(), module);
        }

        if (dyldInfoCommand.exportSize() > 0) {
            ByteBuffer buffer = module.buffer.duplicate();
            buffer.limit((int) (dyldInfoCommand.exportOff() + dyldInfoCommand.exportSize()));
            buffer.position((int) dyldInfoCommand.exportOff());
            processExportNode(log, buffer.slice(), new byte[4000], 0);
        }
    }

    private void rebase(Log log, ByteBuffer buffer, MachOModule module) {
        final List<MemRegion> regions = module.getRegions();
        int type = 0;
        int segmentIndex;
        long address = module.base;
        long segmentEndAddress = module.base + module.size;
        int count;
        int skip;
        boolean done = false;
        while (!done && buffer.hasRemaining()) {
            int b = buffer.get() & 0xff;
            int immediate = b & REBASE_IMMEDIATE_MASK;
            int opcode = b & REBASE_OPCODE_MASK;
            switch (opcode) {
                case REBASE_OPCODE_DONE:
                    done = true;
                    break;
                case REBASE_OPCODE_SET_TYPE_IMM:
                    type = immediate;
                    break;
                case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    segmentIndex = immediate;
                    if (segmentIndex >= regions.size()) {
                        throw new IllegalStateException(String.format("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (0..%d)", segmentIndex, regions.size() - 1));
                    }
                    MemRegion region = regions.get(segmentIndex);
                    address = region.begin + Utils.readULEB128(buffer).longValue();
                    segmentEndAddress = region.end;
                    break;
                case REBASE_OPCODE_ADD_ADDR_ULEB:
                    address += Utils.readULEB128(buffer).longValue();
                    break;
                case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                    address += (immediate * emulator.getPointerSize());
                    break;
                case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                    for (int i = 0; i < immediate; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        rebaseAt(log, type, address, module);
                        address += emulator.getPointerSize();
                    }
                    break;
                case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                    count = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        rebaseAt(log, type, address, module);
                        address += emulator.getPointerSize();
                    }
                    break;
                case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    rebaseAt(log, type, address, module);
                    address += (Utils.readULEB128(buffer).longValue() + emulator.getPointerSize());
                    break;
                case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                    count = Utils.readULEB128(buffer).intValue();
                    skip = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        rebaseAt(log, type, address, module);
                        address += (skip + emulator.getPointerSize());
                    }
                    break;
                default:
                    throw new IllegalStateException("bad rebase opcode=0x" + Integer.toHexString(opcode));
            }
        }
    }

    private void rebaseAt(Log log, int type, long address, Module module) {
        Pointer pointer = UnicornPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalStateException();
        }
        Pointer newPointer = pointer.getPointer(0);
        Pointer old = newPointer;
        if (newPointer == null) {
            newPointer = UnicornPointer.pointer(emulator, module.base);
        } else {
            newPointer = newPointer.share(module.base);
        }
        log.debug("rebaseAt type=" + type + ", address=0x" + Long.toHexString(address - module.base) + ", module=" + module.name + ", old=" + old + ", new=" + newPointer);
        switch (type) {
            case REBASE_TYPE_POINTER:
            case REBASE_TYPE_TEXT_ABSOLUTE32:
                pointer.setPointer(0, newPointer);
                break;
            default:
                throw new IllegalStateException("bad rebase type " + type);
        }
    }

    private void bindLocalRelocations(MachOModule module) {
        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (dysymtabCommand.nLocRel() <= 0) {
            return;
        }

        ByteBuffer buffer = module.buffer;
        buffer.limit((int) (dysymtabCommand.locRelOff() + dysymtabCommand.nLocRel() * 8));
        buffer.position((int) dysymtabCommand.locRelOff());
        ByteBuffer slice = buffer.slice();
        slice.order(ByteOrder.LITTLE_ENDIAN);

        Log log = LogFactory.getLog("cn.banny.emulator.ios." + module.name);

        for (int i = 0; i < dysymtabCommand.nLocRel(); i++) {
            Relocation relocation = Relocation.create(slice);
            if (relocation.pcRel || relocation.extern || relocation.scattered ||
                    relocation.length != (emulator.getPointerSize() == 8 ? 3 : 2) ||
                    relocation.type != ARM_RELOC_VANILLA) {
                throw new IllegalStateException("Unexpected relocation found.");
            }

            buffer.limit(relocation.address + emulator.getPointerSize());
            buffer.position(relocation.address);
            long target = emulator.getPointerSize() == 8 ? buffer.getLong() : buffer.getInt();
            Pointer pointer = UnicornPointer.pointer(emulator, module.base + relocation.address);
            if (pointer == null) {
                throw new IllegalStateException();
            }
            pointer.setPointer(0, UnicornPointer.pointer(emulator, module.base + target));
            if (log.isDebugEnabled()) {
                log.debug("bindLocalRelocations address=0x" + Integer.toHexString(relocation.address) + ", symbolNum=0x" + Integer.toHexString(relocation.symbolNum) + ", target=0x" + Long.toHexString(target));
            }
        }
    }

    private void bindExternalRelocations(MachOModule module) throws IOException {
        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (dysymtabCommand.nExtRel() <= 0) {
            return;
        }

        ByteBuffer buffer = module.buffer;
        buffer.limit((int) (dysymtabCommand.extRelOff() + dysymtabCommand.nExtRel() * 8));
        buffer.position((int) dysymtabCommand.extRelOff());
        ByteBuffer slice = buffer.slice();
        slice.order(ByteOrder.LITTLE_ENDIAN);

        Log log = LogFactory.getLog("cn.banny.emulator.ios." + module.name);

        for (int i = 0; i < dysymtabCommand.nExtRel(); i++) {
            Relocation relocation = Relocation.create(slice);
            if (relocation.pcRel || !relocation.extern || relocation.scattered ||
                    relocation.length != (emulator.getPointerSize() == 8 ? 3 : 2) ||
                    relocation.type != ARM_RELOC_VANILLA) {
                throw new IllegalStateException("Unexpected relocation found.");
            }

            MachOSymbol symbol = module.getSymbolByIndex(relocation.symbolNum);
            Pointer pointer = UnicornPointer.pointer(emulator, module.base + relocation.address);
            if (pointer == null) {
                throw new IllegalStateException();
            }

            boolean isWeakRef = (symbol.nlist.desc() & N_WEAK_REF) != 0;
            long address = resolveSymbol(module, symbol);

            if (address == 0L) {
                log.warn("bindExternalRelocations failed symbol=" + symbol + ", isWeakRef=" + isWeakRef);
            } else {
                pointer.setPointer(0, UnicornPointer.pointer(emulator, address));
                log.debug("bindExternalRelocations address=0x" + Long.toHexString(relocation.address) + ", symbolNum=0x" + Integer.toHexString(relocation.symbolNum) + ", symbolName=" + symbol.getName());
            }
        }
    }

    private long resolveSymbol(Module module, Symbol symbol) throws IOException {
        Symbol replace = module.findSymbolByName(symbol.getName(), true);
        long address = replace == null ? 0L : replace.getAddress();
        for (HookListener listener : hookListeners) {
            long hook = listener.hook(emulator.getSvcMemory(), replace == null ? module.name : replace.getModuleName(), symbol.getName(), address);
            if (hook > 0) {
                address = hook;
                break;
            }
        }
        return address;
    }

    private void bindIndirectSymbolPointers(MachOModule module) throws IOException {
        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (module.indirectSymbolBound) {
            return;
        }
        module.indirectSymbolBound = true;

        List<Long> indirectTable = dysymtabCommand.indirectSymbols();
        Log log = LogFactory.getLog("cn.banny.emulator.ios." + module.name);

        MachO.DyldInfoCommand dyldInfoCommand = module.dyldInfoCommand;
        if (dyldInfoCommand == null) {
            bindLocalRelocations(module);

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
                                    if (log.isDebugEnabled()) {
                                        log.debug("bindIndirectSymbolPointers pointer=" + pointer + ", newPointer=" + newPointer);
                                    }
                                    pointer.setPointer(0, newPointer);
                                    continue;
                                }

                                MachOSymbol symbol = module.getSymbolByIndex((int) symbolIndex);
                                if (symbol == null) {
                                    log.warn("bindIndirectSymbolPointers symbol is null");
                                    continue;
                                }

                                boolean isWeakRef = (symbol.nlist.desc() & N_WEAK_REF) != 0;
                                long address = resolveSymbol(module, symbol);

                                UnicornPointer pointer = UnicornPointer.pointer(emulator, ptrToBind + module.base);
                                if (pointer == null) {
                                    throw new IllegalStateException("pointer=" + pointer);
                                }
                                if (address == 0L) {
                                    if (isWeakRef) {
                                        log.info("bindIndirectSymbolPointers symbol=" + symbol + ", isWeakRef=" + isWeakRef);
                                        pointer.setPointer(0, null);
                                    } else {
                                        log.warn("bindIndirectSymbolPointers failed symbol=" + symbol);
                                    }
                                } else {
                                    pointer.setPointer(0, UnicornPointer.pointer(emulator, address));
                                    log.debug("bindIndirectSymbolPointers symbolIndex=0x" + Long.toHexString(symbolIndex) + ", symbol=" + symbol + ", ptrToBind=0x" + Long.toHexString(ptrToBind));
                                }
                            }
                        }
                        break;
                    case SEGMENT_64:
                        throw new UnsupportedOperationException("bindIndirectSymbolPointers SEGMENT_64");
                }
            }

            bindExternalRelocations(module);
        } else {
            if (dyldInfoCommand.bindSize() > 0) {
                ByteBuffer buffer = module.buffer.duplicate();
                buffer.limit((int) (dyldInfoCommand.bindOff() + dyldInfoCommand.bindSize()));
                buffer.position((int) dyldInfoCommand.bindOff());
                eachBind(log, buffer.slice(), module, false);
            }
            if (dyldInfoCommand.lazyBindSize() > 0) {
                ByteBuffer buffer = module.buffer.duplicate();
                buffer.limit((int) (dyldInfoCommand.lazyBindOff() + dyldInfoCommand.lazyBindSize()));
                buffer.position((int) dyldInfoCommand.lazyBindOff());
                eachBind(log, buffer.slice(), module, true);
            }
        }
    }

    private void eachBind(Log log, ByteBuffer buffer, MachOModule module, boolean lazy) throws IOException {
        final List<MemRegion> regions = module.getRegions();
        int type = lazy ? BIND_TYPE_POINTER : 0;
        int segmentIndex;
        long address = module.base;
        long segmentEndAddress = address + module.size;
        String symbolName = null;
        int symbolFlags = 0;
        long libraryOrdinal = 0;
        long addend = 0;
        int count;
        int skip;
        boolean done = false;
        while (!done && buffer.hasRemaining()) {
            int b = buffer.get() & 0xff;
            int immediate = b & BIND_IMMEDIATE_MASK;
            int opcode = b & BIND_OPCODE_MASK;
            switch (opcode) {
                case BIND_OPCODE_DONE:
                    if (!lazy) {
                        done = true;
                    }
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
                    symbolFlags = immediate;
                    break;
                case BIND_OPCODE_SET_TYPE_IMM:
                    type = immediate;
                    break;
                case BIND_OPCODE_SET_ADDEND_SLEB:
                    addend = Utils.readULEB128(buffer).longValue();
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
                    doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                    address += emulator.getPointerSize();
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                    address += (Utils.readULEB128(buffer).longValue() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                    address += (immediate*emulator.getPointerSize() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    count = Utils.readULEB128(buffer).intValue();
                    skip = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module, lazy);
                        address += (skip + emulator.getPointerSize());
                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("bad bind opcode 0x%s in bind info", Integer.toHexString(opcode)));
            }
        }
    }

    private void doBindAt(Log log, long libraryOrdinal, int type, long address, String symbolName, int symbolFlags, long addend, MachOModule module, boolean lazy) throws IOException {
        Symbol symbol = module.findSymbolByName(symbolName, true);
        if (symbol == null) {
            log.warn("doBindAt type=" + type + ", symbolName=" + symbolName + ", address=0x" + Long.toHexString(address - module.base) + ", lazy=" + lazy + ", upwardLibraries=" + module.upwardLibraries);
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("doBindAt libraryOrdinal=" + libraryOrdinal + ", type=" + type + ", symbolName=" + symbolName + ", symbolFlags=" + symbolFlags + ", addend=" + addend + ", address=0x" + Long.toHexString(address - module.base) + ", lazy=" + lazy + ", symbol=" + symbol);
        }
        Pointer pointer = UnicornPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalStateException();
        }

        long bindAt = symbol.getAddress();
        for (HookListener listener : hookListeners) {
            long hook = listener.hook(emulator.getSvcMemory(), symbol.getModuleName(), symbol.getName(), bindAt);
            if (hook > 0) {
                bindAt = hook;
                break;
            }
        }

        Pointer newPointer = UnicornPointer.pointer(emulator, bindAt);
        if (newPointer == null) {
            newPointer = UnicornPointer.pointer(emulator, addend);
        } else {
            newPointer = newPointer.share(addend);
        }
        switch (type) {
            case BIND_TYPE_POINTER:
                pointer.setPointer(0, newPointer);
                break;
            case BIND_TYPE_TEXT_ABSOLUTE32:
                pointer.setInt(0, (int) (symbol.getAddress() + addend));
                break;
            default:
                throw new IllegalStateException("bad bind type " + type);
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

    private Symbol malloc;

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        if (runtime) {
            return MemoryBlockImpl.alloc(this, length);
        } else {
            return MemoryAllocBlock.malloc(emulator, malloc, length);
        }
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
