package com.github.unidbg.ios;

import com.github.unidbg.Alignment;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Svc;
import com.github.unidbg.Symbol;
import com.github.unidbg.Utils;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmHook;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.IOConstants;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.ios.patch.LibDyldPatcher;
import com.github.unidbg.ios.struct.kernel.Pthread;
import com.github.unidbg.ios.struct.kernel.Pthread32;
import com.github.unidbg.ios.struct.kernel.Pthread64;
import com.github.unidbg.ios.struct.kernel.VmRemapRequest;
import com.github.unidbg.ios.struct.sysctl.DyldImageInfo32;
import com.github.unidbg.ios.struct.sysctl.DyldImageInfo64;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryAllocBlock;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.MemoryBlockImpl;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.spi.AbstractLoader;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.spi.Loader;
import com.github.unidbg.thread.Task;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MachOLoader extends AbstractLoader<DarwinFileIO> implements Memory, Loader, com.github.unidbg.ios.MachO {

    private static final Logger log = LoggerFactory.getLogger(MachOLoader.class);

    private boolean objcRuntime;

    MachOLoader(Emulator<DarwinFileIO> emulator, UnixSyscallHandler<DarwinFileIO> syscallHandler, String[] envs) {
        super(emulator, syscallHandler);

        stackSize = STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        backend.mem_map(STACK_BASE - stackSize, stackSize, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

        setStackPoint(STACK_BASE);
        initializeTSD(envs);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void setLibraryResolver(LibraryResolver libraryResolver) {
        if (libraryResolver instanceof IOResolver) {
            syscallHandler.addIOResolver((IOResolver<DarwinFileIO>) libraryResolver);
        }
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
        return new MachOLibraryFile(file);
    }

    public void setObjcRuntime(boolean objcRuntime) {
        this.objcRuntime = objcRuntime;
    }

    private UnidbgPointer vars;
    private Pointer errno;

    final void setErrnoPointer(Pointer errno) {
        this.errno = errno.getPointer(0);
        this.setErrno(0);
    }

    public static final long __TSD_THREAD_SELF = 0;
    public static final long __TSD_ERRNO = 1;
    public static final long __TSD_MIG_REPLY = 2;
//    private static final int __PTK_FRAMEWORK_OBJC_KEY5 = 0x2d;

    private void initializeTSD(String[] envs) {
        List<String> envList = new ArrayList<>();
        envList.add("MallocCorruptionAbort=0");
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

        UnidbgPointer _NSGetEnviron = allocateStack(emulator.getPointerSize());
        _NSGetEnviron.setPointer(0, environ);

        final Pointer programName = writeStackString(emulator.getProcessName());
        Pointer _NSGetProgname = allocateStack(emulator.getPointerSize());
        _NSGetProgname.setPointer(0, programName);

        Pointer _NSGetArgc = allocateStack(emulator.getPointerSize());
        _NSGetArgc.setInt(0, 1);

        Pointer args = allocateStack(emulator.getPointerSize());
        args.setPointer(0, programName);
        Pointer _NSGetArgv = allocateStack(emulator.getPointerSize());
        _NSGetArgv.setPointer(0, args);

        vars = allocateStack(emulator.getPointerSize() * 5);
        vars.setPointer(0, null); // _NSGetMachExecuteHeader
        vars.setPointer(emulator.getPointerSize(), _NSGetArgc);
        vars.setPointer(2L * emulator.getPointerSize(), _NSGetArgv);
        vars.setPointer(3L * emulator.getPointerSize(), _NSGetEnviron);
        vars.setPointer(4L * emulator.getPointerSize(), _NSGetProgname);

        final Pointer thread = allocateStack(UnidbgStructure.calculateSize(emulator.is64Bit() ? Pthread64.class : Pthread32.class)); // reserve space for pthread_internal_t
        Pthread pthread = Pthread.create(emulator, thread);

        /* 0xa4必须固定，否则初始化objc会失败 */
        final UnidbgPointer tsd = pthread.getTSD(); // tsd size
        assert tsd != null;
        tsd.setPointer(__TSD_THREAD_SELF, thread);
        tsd.setPointer(__TSD_ERRNO * emulator.getPointerSize(), errno);
        tsd.setPointer(__TSD_MIG_REPLY * emulator.getPointerSize(), null);

        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tsd.peer);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDRRO_EL0, tsd.peer);
        }

        long sp = getStackPoint();
        sp &= (~(emulator.is64Bit() ? 15 : 7));
        setStackPoint(sp);

        if (log.isDebugEnabled()) {
            log.debug("initializeTSD tsd={}, thread={}, environ={}, vars={}, sp=0x{}, errno={}", tsd, thread, environ, vars, Long.toHexString(getStackPoint()), errno);
        }

        addModuleListener(new LibDyldPatcher(_NSGetArgc, _NSGetArgv, _NSGetEnviron, _NSGetProgname));
    }

    public final void onExecutableLoaded(String executable) {
        if (callInitFunction) {
            for (MachOModule m : modules.values().toArray(new MachOModule[0])) {
                boolean needCallInit = m.symbolNotBound.isEmpty() || isPayloadModule(m) || m.getPath().equals(executable);
                if (needCallInit) {
                    m.doInitialization(emulator);
                }
            }
        }
    }

    @Override
    protected Module loadInternal(LibraryFile libraryFile, boolean forceCallInit) {
        try {
            return loadInternal(libraryFile, forceCallInit, true);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private MachOModule loadInternal(LibraryFile libraryFile, boolean forceCallInit, boolean checkBootstrap) throws IOException {
        MachOModule module = loadInternalPhase(libraryFile, true, checkBootstrap, Collections.emptyList());

        for (MachOModule export : modules.values().toArray(new MachOModule[0])) {
            for (NeedLibrary library : export.lazyLoadNeededList.toArray(new NeedLibrary[0])) {
                String neededLibrary = library.path;
                if (log.isDebugEnabled()) {
                    log.debug("{} need dependency {}", export.getPath(), neededLibrary);
                }

                MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
                if (loaded != null) {
                    if (library.upward) {
                        export.upwardLibraries.put(FilenameUtils.getBaseName(neededLibrary), loaded);
                    }
                    continue;
                }
                LibraryFile neededLibraryFile = resolveLibrary(libraryFile, neededLibrary, Collections.singletonList(FilenameUtils.getFullPath(libraryFile.getPath())));
                if (neededLibraryFile != null) {
                    MachOModule needed = loadInternalPhase(neededLibraryFile, true, false, Collections.emptySet());
                    needed.addReferenceCount();

                    if (library.upward) {
                        export.upwardLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
                    }
                } else if (!library.weak) {
                    log.info("{} load NOT weak dependency {} failed", export.getPath(), neededLibrary);
                }
            }
            export.lazyLoadNeededList.clear();
        }

        for (MachOModule m : modules.values()) {
            processBind(m);

            m.callObjcNotifyMapped(_objcNotifyMapped);
        }

        notifySingle(Dyld.dyld_image_state_bound, module);
        notifySingle(Dyld.dyld_image_state_dependents_initialized, module);

        if (callInitFunction || forceCallInit) {
            MachOModule[] modules = this.modules.values().toArray(new MachOModule[0]);
            for (MachOModule m : modules) {
                if (isPayloadModule(m)) {
                    continue;
                }
                if (m.symbolNotBound.isEmpty() || forceCallInit) {
                    m.callObjcNotifyInit(_objcNotifyInit);
                    m.doInitialization(emulator);
                }
            }
        }

        for (MachOModule m : modules.values().toArray(new MachOModule[0])) {
            notifySingle(Dyld.dyld_image_state_initialized, m);
        }

        return module;
    }

    private com.github.unidbg.ios.Loader loader;

    public void setLoader(com.github.unidbg.ios.Loader loader) {
        this.loader = loader;
    }

    final boolean isPayloadModule(Module module) {
        return loader != null && loader.isPayloadModule(module.getPath());
    }

    private MachOModule loadInternalPhase(LibraryFile libraryFile, boolean loadNeeded, boolean checkBootstrap, Collection<String> parentRpath) {
        try {
            ByteBuffer buffer = libraryFile.mapBuffer();
            return loadInternalPhase(libraryFile, buffer, loadNeeded, checkBootstrap, parentRpath);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private MachOModule loadInternalPhase(LibraryFile libraryFile, ByteBuffer buffer,
                                          boolean loadNeeded, boolean checkBootstrap, Collection<String> parentRpath) throws IOException {
        MachO machO = new MachO(new ByteBufferKaitaiStream(buffer));
        MachO.MagicType magic = machO.magic();
        switch (magic) {
            case FAT_BE:
                Map<Long, MachO.FatArch> archMap = new HashMap<>();
                for (MachO.FatArch arch : machO.fatHeader().fatArchs()) {
                    if ((arch.cputype() == MachO.CpuType.ARM && emulator.is32Bit()) || (arch.cputype() == MachO.CpuType.ARM64 && emulator.is64Bit())) {
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
                    if (log.isDebugEnabled()) {
                        log.debug("loadFatArch={}, cpuSubType={}", arch.cputype(), arch.cpusubtype());
                    }
                    return loadInternalPhase(libraryFile, buffer.slice(), loadNeeded, checkBootstrap, parentRpath);
                }
                throw new IllegalArgumentException("find arch failed");
            case MACHO_LE_X86: // ARM
                if (machO.header().cputype() != MachO.CpuType.ARM) {
                    throw new UnsupportedOperationException("cpuType=" + machO.header().cputype());
                }
                if (emulator.is64Bit()) {
                    throw new UnsupportedOperationException("NOT 64 bit executable: " + libraryFile.getName());
                }
                break;
            case MACHO_LE_X64:
                if (machO.header().cputype() != MachO.CpuType.ARM64) {
                    throw new UnsupportedOperationException("cpuType=" + machO.header().cputype());
                }
                if (emulator.is32Bit()) {
                    throw new UnsupportedOperationException("NOT 32 bit executable: " + libraryFile.getName());
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

        final boolean isExecutable = machO.header().filetype() == MachO.FileType.EXECUTE;
        final boolean isPositionIndependent = (machO.header().flags() & MH_PIE) != 0;

        if (checkBootstrap && !isExecutable && executableModule == null) {
            URL url = getClass().getResource(objcRuntime ? "/ios/bootstrap_objc" : "/ios/bootstrap");
            String path = "unidbg_bootstrap";
            if (libraryFile instanceof DarwinLibraryFile) {
                path = ((DarwinLibraryFile) libraryFile).resolveBootstrapPath();
            }
            loadInternal(new URLibraryFile(url, path, null), false, false);
        }

        long start = System.currentTimeMillis();
        long size = 0;
        String dyId = libraryFile.getName();
        MachO.DyldInfoCommand dyldInfoCommand = null;
        MachO.LinkeditDataCommand chainedFixups = null;
        MachOModule subModule = null;
        boolean finalSegment = false;
        Set<String> rpathSet = new LinkedHashSet<>(2);
        byte[] uuid = null;
        String dylibPath = FilenameUtils.normalize(libraryFile.getPath(), true);

        for (MachO.LoadCommand command : machO.loadCommands()) {
            if (command == null) {
                throw new NullPointerException();
            }

            switch (command.type()) {
                case DYLD_INFO:
                case DYLD_INFO_ONLY:
                    if (dyldInfoCommand != null) {
                        throw new IllegalStateException("dyldInfoCommand=" + dyldInfoCommand);
                    }
                    dyldInfoCommand = (MachO.DyldInfoCommand) command.body();
                    break;
                case DYLD_CHAINED_FIXUPS:
                    if (chainedFixups != null) {
                        throw new IllegalStateException("chainedFixups=" + chainedFixups);
                    }
                    chainedFixups = (MachO.LinkeditDataCommand) command.body();
                    break;
                case SEGMENT: {
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    if ("__PAGEZERO".equals(segmentCommand.segname())) {
                        break;
                    }
                    if (segmentCommand.filesize() > segmentCommand.vmsize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment load command %s filesize is larger than vmsize", command.type()));
                    }
                    if (finalSegment) {
                        throw new IllegalStateException("finalSegment");
                    }
                    if (((segmentCommand.vmaddr() + segmentCommand.vmsize()) % emulator.getPageAlign()) != 0) {
                        finalSegment = true;
                    }
                    if (segmentCommand.vmaddr() % emulator.getPageAlign() != 0) {
                        throw new IllegalArgumentException("vmaddr not page aligned");
                    }

                    if (segmentCommand.vmsize() == 0) {
                        break;
                    }
                    if (segmentCommand.vmsize() < segmentCommand.filesize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment %s has vmsize < filesize", command.type()));
                    }
                    long vmsize = ARM.alignSize(segmentCommand.vmsize(), emulator.getPageAlign());
                    long high = segmentCommand.vmaddr() + vmsize;
                    if (size < high) {
                        size = high;
                    }
                    break;
                }
                case SEGMENT_64: {
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if ("__PAGEZERO".equals(segmentCommand64.segname())) {
                        break;
                    }
                    if (segmentCommand64.filesize() > segmentCommand64.vmsize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment load command %s filesize is larger than vmsize", command.type()));
                    }
                    if (finalSegment) {
                        throw new IllegalStateException("finalSegment");
                    }
                    if (((segmentCommand64.vmaddr() + segmentCommand64.vmsize()) % emulator.getPageAlign()) != 0) {
                        finalSegment = true;
                    }
                    if (segmentCommand64.vmaddr() % emulator.getPageAlign() != 0) {
                        throw new IllegalArgumentException("vmaddr not page aligned");
                    }

                    if (segmentCommand64.vmsize() == 0) {
                        break;
                    }
                    if (segmentCommand64.vmsize() < segmentCommand64.filesize()) {
                        throw new IllegalStateException(String.format("malformed mach-o image: segment %s has vmsize < filesize", command.type()));
                    }
                    long vmsize = ARM.alignSize(segmentCommand64.vmsize(), emulator.getPageAlign());
                    long high = segmentCommand64.vmaddr() + vmsize;
                    if (size < high) {
                        size = high;
                    }
                    break;
                }
                case ID_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    String dylibName = dylibCommand.name();
                    if (loader != null && loader.isPayloadModule(dylibPath)) {
                        dylibPath = dylibPath.replace("@executable_path/", "");
                    } else if (dylibName.startsWith("/")) {
                        dylibPath = dylibName;
                    }
                    int index = dylibPath.indexOf('/'); // unidbg build frameworks
                    if (index != -1) {
                        String first = dylibPath.substring(0, index);
                        String second = dylibPath.substring(index + 1);
                        if (first.equals(second)) {
                            dylibPath = "/System/Library/Frameworks/" + first + ".framework/" + first;
                        }
                    }
                    dyId = FilenameUtils.getName(dylibName);
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
                        throw new UnsupportedOperationException("Encrypted file: " + libraryFile.getName());
                    }
                    break;
                case UUID:
                    MachO.UuidCommand uuidCommand = (MachO.UuidCommand) command.body();
                    uuid = uuidCommand.uuid();
                    break;
                case FUNCTION_STARTS:
                case DATA_IN_CODE:
                case CODE_SIGNATURE:
                case SOURCE_VERSION:
                case SEGMENT_SPLIT_INFO:
                case DYLIB_CODE_SIGN_DRS:
                case SUB_FRAMEWORK:
                case VERSION_MIN_IPHONEOS:
                case LOAD_DYLINKER:
                case MAIN:
                case ROUTINES:
                case ROUTINES_64:
                case LOAD_WEAK_DYLIB:
                case BUILD_VERSION:
                case DYLD_EXPORTS_TRIE:
                    break;
                case SUB_CLIENT:
                    MachO.SubCommand subCommand = (MachO.SubCommand) command.body();
                    String name = subCommand.name().value();
                    MachOModule module = (MachOModule) findModule(name);
                    if (module == null) {
                        log.debug("Find sub client failed: {}", name);
                    } else {
                        subModule = module;
                    }
                    break;
                case RPATH:
                    MachO.RpathCommand rpathCommand = (MachO.RpathCommand) command.body();
                    String rpath = rpathCommand.path();
                    if (!rpath.contains("@loader_path/")) {
                        rpathSet.add(rpath);
                    }
                    break;
                default:
                    log.info("Not handle loadCommand={}, dylibPath={}", command.type(), dylibPath);
                    break;
            }
        }
        rpathSet.addAll(parentRpath);

        final long loadBase = isExecutable ? 0 : mmapBaseAddress;
        long machHeader = -1;
        if (isExecutable) {
            long end = loadBase + size;
            if (end >= mmapBaseAddress) {
                setMMapBaseAddress(end);
            }
        } else {
            setMMapBaseAddress(loadBase + size);
        }

        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(uuid, "start map dyid=" + dyId + ", base=0x" + Long.toHexString(loadBase) + ", size=0x" + Long.toHexString(size) + ", rpath=" + rpathSet + ", uuid=" + Utils.toUUID(uuid)));
        }

        final List<NeedLibrary> neededList = new ArrayList<>();
        final List<MemRegion> regions = new ArrayList<>(5);
        final List<MachO.DylibCommand> exportDylibs = new ArrayList<>();
        MachO.SymtabCommand symtabCommand = null;
        MachO.DysymtabCommand dysymtabCommand = null;
        MachO.EntryPointCommand entryPointCommand = null;
        List<String> ordinalList = new ArrayList<>();
        Section fEHFrameSection = null;
        Section fUnwindInfoSection = null;
        Map<String, MachO.SegmentCommand64.Section64> objcSections = new HashMap<>();
        List<Segment> segments = new ArrayList<>(10);
        for (MachO.LoadCommand command : machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT: {
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    long begin = loadBase + segmentCommand.vmaddr();
                    if ("__PAGEZERO".equals(segmentCommand.segname())) {
                        segments.add(new Segment(segmentCommand.vmaddr(), segmentCommand.vmsize(), segmentCommand.fileoff(), segmentCommand.filesize()));
                        regions.add(new MemRegion(begin, begin, begin + segmentCommand.vmsize(), 0, libraryFile, segmentCommand.vmaddr()));
                        break;
                    }

                    segments.add(new Segment(segmentCommand.vmaddr(), segmentCommand.vmsize(), segmentCommand.fileoff(), segmentCommand.filesize()));
                    boolean isTextSeg = "__TEXT".equals(segmentCommand.segname());
                    for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                        String sectName = section.sectName();
                        checkSection(dyId, segmentCommand.segname(), sectName);
                    }

                    if (segmentCommand.vmsize() == 0) {
                        regions.add(new MemRegion(begin, begin, begin, 0, libraryFile, segmentCommand.vmaddr()));
                        break;
                    }
                    int prot = get_segment_protection(segmentCommand.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    if (machHeader == -1 && isTextSeg) {
                        machHeader = begin;
                    }
                    Alignment alignment = this.mem_map(begin, segmentCommand.vmsize(), prot, dyId, emulator.getPageAlign());
                    write_mem((int) segmentCommand.fileoff(), (int) segmentCommand.filesize(), begin, buffer);

                    regions.add(new MemRegion(begin, alignment.address, alignment.address + alignment.size, prot, libraryFile, segmentCommand.vmaddr()));
                    break;
                }
                case SEGMENT_64: {
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    long begin = loadBase + segmentCommand64.vmaddr();
                    if ("__PAGEZERO".equals(segmentCommand64.segname())) {
                        segments.add(new Segment(segmentCommand64.vmaddr(), segmentCommand64.vmsize(), segmentCommand64.fileoff(), segmentCommand64.filesize()));
                        regions.add(new MemRegion(begin, begin, begin + segmentCommand64.vmsize(), 0, libraryFile, segmentCommand64.vmaddr()));
                        break;
                    }

                    segments.add(new Segment(segmentCommand64.vmaddr(), segmentCommand64.vmsize(), segmentCommand64.fileoff(), segmentCommand64.filesize()));
                    boolean isTextSeg = "__TEXT".equals(segmentCommand64.segname());
                    for (MachO.SegmentCommand64.Section64 section : segmentCommand64.sections()) {
                        String sectName = section.sectName();
                        if (isTextSeg && "__eh_frame".equals(sectName)) {
                            fEHFrameSection = new Section(section.addr(), section.size());
                            continue;
                        }
                        if (isTextSeg && "__unwind_info".equals(sectName)) {
                            fUnwindInfoSection = new Section(section.addr(), section.size());
                            continue;
                        }
                        if (sectName.startsWith("__objc_")) {
                            objcSections.put(sectName, section);
                            continue;
                        }

                        checkSection(dyId, segmentCommand64.segname(), sectName);
                    }

                    if (segmentCommand64.vmsize() == 0) {
                        regions.add(new MemRegion(begin, begin, begin, 0, libraryFile, segmentCommand64.vmaddr()));
                        break;
                    }
                    int prot = get_segment_protection(segmentCommand64.initprot());
                    if (prot == UnicornConst.UC_PROT_NONE) {
                        prot = UnicornConst.UC_PROT_ALL;
                    }

                    if (machHeader == -1 && isTextSeg) {
                        machHeader = begin;
                    }
                    Alignment alignment = this.mem_map(begin, segmentCommand64.vmsize(), prot, dyId, emulator.getPageAlign());
                    if (log.isDebugEnabled()) {
                        log.debug("mem_map address=0x{}, size=0x{}", Long.toHexString(alignment.address), Long.toHexString(alignment.size));
                    }
                    write_mem((int) segmentCommand64.fileoff(), (int) segmentCommand64.filesize(), begin, buffer);

                    regions.add(new MemRegion(begin, alignment.address, alignment.address + alignment.size, prot, libraryFile, segmentCommand64.vmaddr()));
                    break;
                }
                case LOAD_DYLIB: {
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    ordinalList.add(dylibCommand.name());
                    neededList.add(new NeedLibrary(dylibCommand.name(), false, false));
                    break;
                }
                case LOAD_WEAK_DYLIB: {
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    ordinalList.add(dylibCommand.name());
                    neededList.add(new NeedLibrary(dylibCommand.name(), true, true));
                    break;
                }
                case REEXPORT_DYLIB: {
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    ordinalList.add(dylibCommand.name());
                    exportDylibs.add((MachO.DylibCommand) command.body());
                    break;
                }
                case LAZY_LOAD_DYLIB: {
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    ordinalList.add(dylibCommand.name());
                    break;
                }
                case LOAD_UPWARD_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    ordinalList.add(dylibCommand.name());
                    neededList.add(new NeedLibrary(dylibCommand.name(), true, false));
                    break;
                case SYMTAB:
                    symtabCommand = (MachO.SymtabCommand) command.body();
                    break;
                case DYSYMTAB:
                    dysymtabCommand = (MachO.DysymtabCommand) command.body();
                    break;
                case MAIN:
                    entryPointCommand = (MachO.EntryPointCommand) command.body();
                    break;
            }
        }
        Logger log = LoggerFactory.getLogger("com.github.unidbg.ios." + dyId);
        if (!log.isDebugEnabled()) {
            log = MachOLoader.log;
        }
        if (log.isDebugEnabled()) {
            log.debug("load dyId={}, base=0x{}, dyldInfoCommand={}, loadNeeded={}, regions={}, isPositionIndependent={}", dyId, Long.toHexString(loadBase), dyldInfoCommand, loadNeeded, regions, isPositionIndependent);
        }

        Map<String, Module> exportModules = new LinkedHashMap<>();

        if (rpathSet.isEmpty()) {
            rpathSet.add(FilenameUtils.getFullPath(dylibPath));
        }
        for (MachO.DylibCommand dylibCommand : exportDylibs) {
            String neededLibrary = dylibCommand.name();
            if (log.isDebugEnabled()) {
                log.debug("{} need export dependency {}", dyId, neededLibrary);
            }

            MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
            if (loaded != null) {
                loaded.addReferenceCount();
                exportModules.put(FilenameUtils.getBaseName(loaded.name), loaded);
                continue;
            }
            LibraryFile neededLibraryFile = resolveLibrary(libraryFile, neededLibrary, rpathSet);
            if (neededLibraryFile != null) {
                MachOModule needed = loadInternalPhase(neededLibraryFile, false, false, rpathSet);
                needed.addReferenceCount();
                exportModules.put(FilenameUtils.getBaseName(needed.name), needed);
            } else if(log.isDebugEnabled()) {
                log.debug("{} load export dependency {} failed", dyId, neededLibrary);
            }
        }

        Map<String, MachOModule> neededLibraries = new LinkedHashMap<>();
        Map<String, Module> upwardLibraries = new LinkedHashMap<>();
        final List<NeedLibrary> lazyLoadNeededList;
        if (loadNeeded) {
            lazyLoadNeededList = new ArrayList<>();
            for (NeedLibrary library : neededList) {
                String neededLibrary = library.path;
                if (log.isDebugEnabled()) {
                    log.debug("{} need dependency {}", dyId, neededLibrary);
                }

                MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
                if (loaded != null) {
                    loaded.addReferenceCount();
                    neededLibraries.put(FilenameUtils.getBaseName(loaded.name), loaded);
                    continue;
                }
                if (library.upward) {
                    lazyLoadNeededList.add(library);
                    continue;
                }
                LibraryFile neededLibraryFile = resolveLibrary(libraryFile, neededLibrary, rpathSet);
                if (neededLibraryFile != null) {
                    MachOModule needed = loadInternalPhase(neededLibraryFile, true, false, rpathSet);
                    needed.addReferenceCount();
                    neededLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
                } else if(!library.weak) {
                    if ("/usr/lib/libnetwork.dylib".equals(neededLibrary)) {
                        continue;
                    }
                    log.info("Module \"{}\" load dependency {} failed: rpath={}", dyId, neededLibrary, rpathSet);
                }
            }
        } else {
            lazyLoadNeededList = neededList;
        }

        if (log.isDebugEnabled()) {
            log.debug("load dyId={}, base=0x{}, neededLibraries={}, upwardLibraries={}", dyId, Long.toHexString(loadBase), neededLibraries, upwardLibraries);
        }

        final long loadSize = size;
        MachOModule module = new MachOModule(machO, dyId, loadBase, loadSize, new HashMap<>(neededLibraries), regions,
                symtabCommand, dysymtabCommand, buffer, lazyLoadNeededList, upwardLibraries, exportModules, dylibPath, emulator,
                dyldInfoCommand, chainedFixups, null, null, vars, machHeader, isExecutable, this, hookListeners, ordinalList,
                fEHFrameSection, fUnwindInfoSection, objcSections, segments.toArray(new Segment[0]), libraryFile);
        if (isExecutable) {
            setExecuteModule(module);
        }
        for(MachOModule mm : modules.values()) {
            mm.onLoadNewModule(module);
        }
        modules.put(dyId, module);
        path_modules.put(dylibPath, module);
        if (subModule != null) {
            subModule.exportModules.put(FilenameUtils.getBaseName(module.name), module);
        }

        if (maxDylibName == null || dyId.length() > maxDylibName.length()) {
            maxDylibName = dyId;
        }
        if (loadSize > maxSizeOfDylib) {
            maxSizeOfDylib = loadSize;
        }

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
        processRebase(log, module);

        if ("libsystem_malloc.dylib".equals(dyId)) {
            malloc = module.findSymbolByName("_malloc", false);
            free = module.findSymbolByName("_free", false);
        } else if ("Foundation".equals(dyId)) {
            Symbol _NSSetLogCStringFunction = module.findSymbolByName("__NSSetLogCStringFunction", false);
            if (_NSSetLogCStringFunction == null) {
                throw new IllegalStateException("__NSSetLogCStringFunction is null");
            } else {
                Svc svc = emulator.is32Bit() ? new ArmHook() {
                    @Override
                    protected HookStatus hook(Emulator<?> emulator) {
                        Arm32RegisterContext context = emulator.getContext();
                        Pointer message = context.getR0Pointer();
                        int length = context.getR1Int();
                        boolean withSysLogBanner = context.getR2Int() != 0;
                        __NSSetLogCStringFunction(message, length, withSysLogBanner);
                        return HookStatus.LR(emulator, 0);
                    }
                } : new Arm64Hook() {
                    @Override
                    protected HookStatus hook(Emulator<?> emulator) {
                        Arm64RegisterContext context = emulator.getContext();
                        Pointer message = context.getXPointer(0);
                        int length = context.getXInt(1);
                        boolean withSysLogBanner = context.getXInt(2) != 0;
                        __NSSetLogCStringFunction(message, length, withSysLogBanner);
                        return HookStatus.LR(emulator, 0);
                    }
                };
                _NSSetLogCStringFunction.call(emulator, emulator.getSvcMemory().registerSvc(svc));
            }
        }

        if (entryPointCommand != null) {
            module.setEntryPoint(entryPointCommand.entryOff());
        }

        if (log.isDebugEnabled()) {
            log.debug("Load library {} offset={}ms", dyId, System.currentTimeMillis() - start);
        }
        notifyModuleLoaded(module);
        return module;
    }

    private static final String RPATH = "@rpath";

    private LibraryFile resolveLibrary(LibraryFile libraryFile, String neededLibrary, Collection<String> rpathSet) throws IOException {
        if (rpathSet.isEmpty() || !neededLibrary.contains(RPATH)) {
            LibraryFile neededLibraryFile = libraryFile.resolveLibrary(emulator, neededLibrary);
            if (libraryResolver != null && neededLibraryFile == null) {
                neededLibraryFile = libraryResolver.resolveLibrary(emulator, neededLibrary);
            }
            return neededLibraryFile;
        } else {
            List<String> rpathList = new ArrayList<>(rpathSet);
            Collections.reverse(rpathList);
            for (String rpath : rpathList) {
                String dylibName = neededLibrary.replace(RPATH, rpath);
                LibraryFile neededLibraryFile = libraryFile.resolveLibrary(emulator, dylibName);
                if (libraryResolver != null && neededLibraryFile == null) {
                    neededLibraryFile = libraryResolver.resolveLibrary(emulator, dylibName);
                }
                if (neededLibraryFile != null) {
                    return neededLibraryFile;
                }
            }
            return null;
        }
    }

    private void __NSSetLogCStringFunction(Pointer message, int length, boolean withSysLogBanner) {
        byte[] data = message.getByteArray(0, length);
        String str = new String(data, StandardCharsets.UTF_8);
        if (withSysLogBanner) {
            System.err.println("NSLog: " + str);
        } else {
            System.out.println("NSLog: " + str);
        }
    }

    private void checkSection(String dyId, String segName, String sectName) {
        // __OBJC need fNotifyObjC = true
        if (log.isDebugEnabled()) {
            log.debug("checkSection name={}, dyId={}, segName={}", sectName, dyId, segName);
        }
    }

    private void processRebase(Logger log, MachOModule module) {
        MachO.DyldInfoCommand dyldInfoCommand = module.dyldInfoCommand;
        if (dyldInfoCommand == null) {
            MachO.LinkeditDataCommand chainedFixups = module.chainedFixups;
            if (chainedFixups == null) {
                return;
            }
            ByteBuffer buffer = module.buffer.duplicate();
            buffer.limit((int) (chainedFixups.dataOff() + chainedFixups.dataSize()));
            buffer.position((int) chainedFixups.dataOff()); // dyld_chained_fixups_header
            try (ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(buffer.slice())) {
                fixupAllChainedFixups(io, module, chainedFixups);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return;
        }

        if (dyldInfoCommand.rebaseSize() > 0) {
            ByteBuffer buffer = module.buffer.duplicate();
            buffer.limit((int) (dyldInfoCommand.rebaseOff() + dyldInfoCommand.rebaseSize()));
            buffer.position((int) dyldInfoCommand.rebaseOff());
            rebase(log, buffer.slice(), module);
        }
    }

    private void fixupAllChainedFixups(ByteBufferKaitaiStream io, MachOModule mm, MachO.LinkeditDataCommand chainedFixups) {
        long fixups_version = io.readU4le();
        long starts_offset = io.readU4le(); // offset of dyld_chained_starts_in_image in chain_data
        long imports_offset = io.readU4le(); // offset of imports table in chain_data
        long symbols_offset = io.readU4le(); // offset of symbol strings in chain_data
        int imports_count = (int) io.readU4le(); // number of imported symbol names
        int imports_format = (int) io.readU4le(); // DYLD_CHAINED_IMPORT*
        long symbols_format = io.readU4le(); // 0 => uncompressed, 1 => zlib compressed
        if (fixups_version != 0) {
            throw new IllegalStateException("chained fixups, unknown header version");
        }
        if (starts_offset >= io.size()) {
            throw new IllegalStateException("chained fixups, starts_offset exceeds LC_DYLD_CHAINED_FIXUPS size");
        }
        if (imports_offset >= io.size()) {
            throw new IllegalStateException("chained fixups, imports_offset exceeds LC_DYLD_CHAINED_FIXUPS size");
        }

        ByteBuffer buffer = mm.buffer.duplicate();
        buffer.limit((int) (chainedFixups.dataOff() + chainedFixups.dataSize()));
        buffer.position((int) (chainedFixups.dataOff() + symbols_offset)); // symbolsPool
        try (ByteBufferKaitaiStream symbolsPool = new ByteBufferKaitaiStream(buffer.slice())) {
            long formatEntrySize;
            /*
             * http://localhost:8080/source/xref/dyld/common/MachOAnalyzer.cpp#2814
             * http://localhost:8080/source/xref/dyld/common/MachOAnalyzer.cpp#5778
             */
            List<FixupChains.BindTarget> bindTargets = new ArrayList<>(imports_count);
            switch (imports_format) {
                case FixupChains.DYLD_CHAINED_IMPORT:
                    /*
                     * struct dyld_chained_import {
                     *     uint32_t    lib_ordinal :  8,
                     *                 weak_import :  1,
                     *                 name_offset : 23;
                     * };
                     */
                    formatEntrySize = 4;
                    io.seek(imports_offset);
                    for (int i = 0; i < imports_count; i++) {
                        long raw32 = io.readU4le();
                        int lib_ordinal = (int) (raw32 & 0xff);
                        raw32 >>>= 8;
                        boolean weak_import = (raw32 & 1) != 0;
                        int name_offset = (int) (raw32 >>> 1);
                        if (lib_ordinal > 0xf0) {
                            lib_ordinal = (byte) lib_ordinal;
                        }
                        bindTargets.add(new FixupChains.dyld_chained_import_addend64(lib_ordinal, weak_import, name_offset, 0L));
                    }
                    break;
                case FixupChains.DYLD_CHAINED_IMPORT_ADDEND: {
                    /*
                     * struct dyld_chained_import_addend {
                     *     uint32_t    lib_ordinal :  8,
                     *                 weak_import :  1,
                     *                 name_offset : 23;
                     *     int32_t     addend;
                     * };
                     */
                    formatEntrySize = 8;
                    io.seek(imports_offset);
                    for (int i = 0; i < imports_count; i++) {
                        long raw32 = io.readU4le();
                        int lib_ordinal = (int) (raw32 & 0xff);
                        raw32 >>>= 8;
                        boolean weak_import = (raw32 & 1) != 0;
                        int name_offset = (int) (raw32 >>> 1);
                        long addend = io.readU4le();
                        if (lib_ordinal > 0xf0) {
                            lib_ordinal = (byte) lib_ordinal;
                        }
                        bindTargets.add(new FixupChains.dyld_chained_import_addend64(lib_ordinal, weak_import, name_offset, addend));
                    }
                    break;
                }
                case FixupChains.DYLD_CHAINED_IMPORT_ADDEND64:
                    /*
                     * struct dyld_chained_import_addend64 {
                     *     uint64_t    lib_ordinal : 16,
                     *                 weak_import :  1,
                     *                 reserved    : 15,
                     *                 name_offset : 32;
                     *     uint64_t    addend;
                     * };
                     */
                    formatEntrySize = 16;
                    io.seek(imports_offset);
                    for (int i = 0; i < imports_count; i++) {
                        long raw64 = io.readU8le();
                        int lib_ordinal = (int) (raw64 & 0xffff);
                        raw64 >>>= 16;
                        boolean weak_import = (raw64 & 1) != 0;
                        int name_offset = (int) (raw64 >>> 16);
                        long addend = io.readU8le();
                        if (lib_ordinal > 0xfff0) {
                            lib_ordinal = (short) lib_ordinal;
                        }
                        bindTargets.add(new FixupChains.dyld_chained_import_addend64(lib_ordinal, weak_import, name_offset, addend));
                    }
                    break;
                default:
                    throw new IllegalStateException("chained fixups, unknown imports_format");
            }
            if (FixupChains.greaterThanAddOrOverflow(imports_offset, (formatEntrySize * imports_count), symbols_offset)) {
                throw new IllegalStateException("chained fixups, imports array overlaps symbols");
            }
            if (symbols_format != 0) {
                throw new IllegalStateException("chained fixups, symbols_format unknown");
            }

            io.seek(starts_offset); // dyld_chained_starts_in_image
            int seg_count = (int) io.readU4le();
            if (seg_count != mm.segments.length) {
                if (seg_count > mm.segments.length) {
                    throw new IllegalStateException("chained fixups, seg_count exceeds number of segments");
                }

                // We can have fewer segments than the count, so long as those we are missing have no relocs
                int numNoRelocSegments = 0;
                int numExtraSegments = mm.segments.length - seg_count;
                for (Segment segment : mm.segments) {
                    if (segment.vmSize == 0) {
                        ++numNoRelocSegments;
                    }
                }
                if (numNoRelocSegments != numExtraSegments) {
                    throw new IllegalStateException("chained fixups, seg_count does not match number of segments");
                }
            }
            long[] seg_info_offset = new long[seg_count];
            for (int i = 0; i < seg_count; i++) {
                seg_info_offset[i] = io.readU4le();
            }
            int pointer_format_for_all = -1;
            long maxValidPointerSeen = 0;
            for (int i = 0; i < seg_info_offset.length; i++) {
                long offset = seg_info_offset[i];
                if (offset == 0) {
                    continue;
                }
                io.seek(starts_offset + offset); // dyld_chained_starts_in_segment
                long size = io.readU4le(); // size of this (amount kernel needs to copy)
                if (offset + size > imports_offset) { // endOfStarts
                    throw new IllegalStateException(String.format("chained fixups, dyld_chained_starts_in_segment for segment #%d overruns imports table", i));
                }
                int page_size = io.readU2le(); // 0x1000 or 0x4000
                if ((page_size != 0x1000) && (page_size != 0x4000)) {
                    throw new IllegalStateException(String.format("chained fixups, page_size not 4KB or 16KB in segment #%d", i));
                }
                int pointer_format = io.readU2le(); // DYLD_CHAINED_PTR_*
                if (pointer_format > 12) {
                    throw new IllegalStateException(String.format("chained fixups, unknown pointer_format in segment #%d", i));
                }
                if (pointer_format_for_all == -1) {
                    pointer_format_for_all = pointer_format;
                }
                if (pointer_format != pointer_format_for_all) {
                    throw new IllegalStateException(String.format("chained fixups, pointer_format not same for all segments %d and %d", pointer_format, pointer_format_for_all));
                }
                long segment_offset = io.readU8le(); // offset in memory to start of segment
                if (segment_offset != (mm.segments[i].vmAddr - mm.machHeader) && segment_offset != mm.segments[i].vmAddr) {
                    throw new IllegalStateException(String.format("chained fixups, segment_offset does not match vmaddr from LC_SEGMENT in segment #%d", i));
                }
                long max_valid_pointer = io.readU4le(); // for 32-bit OS, any value beyond this is not a pointer
                if (max_valid_pointer != 0) {
                    if (maxValidPointerSeen == 0) {
                        // record max_valid_pointer values seen
                        maxValidPointerSeen = max_valid_pointer;
                    } else if (maxValidPointerSeen != max_valid_pointer) {
                        throw new IllegalStateException("chained fixups, different max_valid_pointer values seen in different segments");
                    }
                }
                int page_count = io.readU2le(); // how many pages are in array
                if (page_count == 0) {
                    continue;
                }
                for (long pageIndex = 0; pageIndex < page_count; pageIndex++) {
                    int offsetInPage = io.readU2le(); // each entry is offset in each page of first element in chain or DYLD_CHAINED_PTR_START_NONE if no fixups on page
                    if (offsetInPage == FixupChains.DYLD_CHAINED_PTR_START_NONE) {
                        continue;
                    }
                    if ((offsetInPage & FixupChains.DYLD_CHAINED_PTR_START_MULTI) != 0) {
                        throw new UnsupportedOperationException("DYLD_CHAINED_PTR_START_MULTI");
                    } else if (offsetInPage > page_size) {
                        throw new IllegalStateException(String.format("chained fixups, in segment #%d page_start[%d]=0x%04X exceeds page size", i, pageIndex, offsetInPage));
                    }

                    // one chain per page
                    Pointer pageContentStart = UnidbgPointer.pointer(emulator, mm.machHeader + segment_offset + (pageIndex * page_size));
                    assert pageContentStart != null;
                    Pointer chain = pageContentStart.share(offsetInPage);
                    walkChain(mm, chain, pointer_format, bindTargets, symbolsPool);
                }
            }

            if (imports_count != 0) {
                int maxBindOrdinal = 0;
                switch (pointer_format_for_all) {
                    case FixupChains.DYLD_CHAINED_PTR_32:
                        maxBindOrdinal = 0x0fffff; // 20-bits
                        break;
                    case FixupChains.DYLD_CHAINED_PTR_ARM64E:
                    case FixupChains.DYLD_CHAINED_PTR_ARM64E_USERLAND:
                    case FixupChains.DYLD_CHAINED_PTR_ARM64E_OFFSET:
                        maxBindOrdinal = 0x00ffff; // 16-bits
                        break;
                    case FixupChains.DYLD_CHAINED_PTR_64:
                    case FixupChains.DYLD_CHAINED_PTR_64_OFFSET:
                    case FixupChains.DYLD_CHAINED_PTR_ARM64E_USERLAND24:
                        maxBindOrdinal = 0xFFFFFF; // 24 bits
                        break;
                }
                if (imports_count >= maxBindOrdinal) {
                    throw new IllegalStateException(String.format("chained fixups, imports_count (%d) exceeds max of %d", imports_count, maxBindOrdinal));
                }
            }
            if (maxValidPointerSeen != 0) {
                Segment segment = mm.segments[mm.segments.length - 1];
                long lastSegmentLastVMAddr = segment.vmAddr + segment.vmSize;
                if (maxValidPointerSeen < lastSegmentLastVMAddr) {
                    throw new IllegalStateException("chained fixups, max_valid_pointer too small for image");
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * <a href="http://localhost:8080/source/xref/dyld/common/MachOLoaded.cpp#1308">参考实现</a>
     */
    private void walkChain(MachOModule mm, Pointer chain, final int pointer_format, List<FixupChains.BindTarget> bindTargets, ByteBufferKaitaiStream symbolsPool) {
        Logger log = LoggerFactory.getLogger("com.github.unidbg.ios." + mm.name);
        boolean chainEnd = false;
        while (!chainEnd) {
            long raw64 = chain.getLong(0);
            log.trace("handleChain: {}, pointer_format={}, raw64=0x{}", chain, pointer_format, Long.toHexString(raw64));
            FixupChains.handleChain(emulator, mm, hookListeners, pointer_format, chain, raw64, bindTargets, symbolsPool);
            switch (pointer_format) {
                case FixupChains.DYLD_CHAINED_PTR_ARM64E: {
                    long dyld_chained_ptr_arm64e_rebase = chain.getLong(16);
                    int next = (int) ((dyld_chained_ptr_arm64e_rebase >> 51) & 0x7ff);
                    if (next == 0) {
                        chainEnd = true;
                    } else {
                        chain = chain.share(next * 8);
                    }
                    break;
                }
                case FixupChains.DYLD_CHAINED_PTR_64:
                case FixupChains.DYLD_CHAINED_PTR_64_OFFSET:
                    int next = (int) ((raw64 >> 51) & 0xfff);
                    if (next == 0) {
                        chainEnd = true;
                    } else {
                        chain = chain.share(next * 4);
                    }
                    break;
                default:
                    throw new UnsupportedOperationException("pointer_format=" + pointer_format);
            }
        }
    }

    private void rebase(Logger log, ByteBuffer buffer, MachOModule module) {
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
                    address += ((long) immediate * emulator.getPointerSize());
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

    private void rebaseAt(Logger log, int type, long address, Module module) {
        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalStateException();
        }
        Pointer newPointer = pointer.getPointer(0);
        Pointer old = newPointer;
        if (newPointer == null) {
            newPointer = UnidbgPointer.pointer(emulator, module.base);
        } else {
            newPointer = newPointer.share(module.base);
        }
        if (log.isTraceEnabled()) {
            log.trace("rebaseAt type={}, address=0x{}, module={}, old={}, new={}", type, Long.toHexString(address - module.base), module.name, old, newPointer);
        }
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

        Logger log = LoggerFactory.getLogger("com.github.unidbg.ios." + module.name);

        for (int i = 0; i < dysymtabCommand.nLocRel(); i++) {
            Relocation relocation = Relocation.create(slice);
            if (relocation.pcRel || relocation.extern || relocation.scattered ||
                    relocation.length != (emulator.is64Bit() ? 3 : 2) ||
                    relocation.type != ARM_RELOC_VANILLA) {
                throw new IllegalStateException("Unexpected relocation found.");
            }

            buffer.limit(relocation.address + emulator.getPointerSize());
            buffer.position(relocation.address);
            long target = emulator.is64Bit() ? buffer.getLong() : buffer.getInt();
            Pointer pointer = UnidbgPointer.pointer(emulator, module.base + relocation.address);
            if (pointer == null) {
                throw new IllegalStateException();
            }
            pointer.setPointer(0, UnidbgPointer.pointer(emulator, module.base + target));
            if (log.isDebugEnabled()) {
                log.debug("bindLocalRelocations address=0x{}, symbolNum=0x{}, target=0x{}", Integer.toHexString(relocation.address), Integer.toHexString(relocation.symbolNum), Long.toHexString(target));
            }
        }
    }

    private void bindExternalRelocations(MachOModule module) {
        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (dysymtabCommand.nExtRel() <= 0) {
            return;
        }

        ByteBuffer buffer = module.buffer;
        buffer.limit((int) (dysymtabCommand.extRelOff() + dysymtabCommand.nExtRel() * 8));
        buffer.position((int) dysymtabCommand.extRelOff());
        ByteBuffer slice = buffer.slice();
        slice.order(ByteOrder.LITTLE_ENDIAN);

        Logger log = LoggerFactory.getLogger("com.github.unidbg.ios." + module.name);

        for (int i = 0; i < dysymtabCommand.nExtRel(); i++) {
            Relocation relocation = Relocation.create(slice);
            if (relocation.pcRel || !relocation.extern || relocation.scattered ||
                    relocation.length != (emulator.is64Bit() ? 3 : 2) ||
                    relocation.type != ARM_RELOC_VANILLA) {
                throw new IllegalStateException("Unexpected relocation found.");
            }

            MachOSymbol symbol = module.getSymbolByIndex(relocation.symbolNum);
            Pointer pointer = UnidbgPointer.pointer(emulator, module.base + relocation.address);
            if (pointer == null) {
                throw new IllegalStateException();
            }

            boolean isWeakRef = (symbol.nlist.desc() & N_WEAK_REF) != 0;
            long address = resolveSymbol(module, symbol);

            if (address == 0L) {
                if (isWeakRef) {
                    log.debug("bindExternalRelocations failed symbol={}, isWeakRef=true", symbol);
                    pointer.setPointer(0, null);
                } else {
                    log.warn("bindExternalRelocations failed symbol={}, isWeakRef=false", symbol);
                }
                module.addNotBoundSymbol(symbol.getName());
            } else {
                pointer.setPointer(0, UnidbgPointer.pointer(emulator, address));
                if (log.isDebugEnabled()) {
                    log.debug("bindExternalRelocations address=0x{}, symbolNum=0x{}, symbolName={}", Long.toHexString(relocation.address), Integer.toHexString(relocation.symbolNum), symbol.getName());
                }
            }
        }
    }

    private long resolveSymbol(MachOModule module, MachOSymbol symbol) {
        int libraryOrdinal = symbol.getLibraryOrdinal();
        Symbol replace = null;
        if (libraryOrdinal == BIND_SPECIAL_DYLIB_SELF) {
            replace = module.findSymbolByName(symbol.getName(), false);
        } else if (libraryOrdinal <= module.ordinalList.size()) {
            String path = module.ordinalList.get(libraryOrdinal - 1);
            MachOModule targetImage = this.modules.get(FilenameUtils.getName(path));
            if (targetImage != null) {
                replace = findSymbolInternal(targetImage, symbol.getName());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("resolveSymbol libraryOrdinal={}, path={}", libraryOrdinal, path);
                }
            }
        } else {
            throw new IllegalStateException(String.format("bad mach-o binary, library ordinal (%d) too big (max %d) for symbol %s in %s", libraryOrdinal, module.ordinalList.size(), symbol.getName(), module.getPath()));
        }

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

    private Pointer dyldLazyBinder;
    private Pointer dyldFuncLookup;

    private void setupLazyPointerHandler(MachOModule module) {
        if (module.lazyPointerProcessed) {
            return;
        }
        module.lazyPointerProcessed = true;

        if (module.isVirtual()) { // virtual module
            return;
        }

        for (MachO.LoadCommand command : module.machO.loadCommands()) {
            switch (command.type()) {
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    if ("__DATA".equals(segmentCommand.segname())) {
                        for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                            if ("__dyld".equals(section.sectName())) {
                                Pointer dd = UnidbgPointer.pointer(emulator, module.base + section.addr());
                                if (dyldLazyBinder == null) {
                                    dyldLazyBinder = emulator.getSvcMemory().registerSvc(new ArmSvc() {
                                        @Override
                                        public long handle(Emulator<?> emulator) {
                                            return ((Dyld) emulator.getDlfcn())._stub_binding_helper();
                                        }
                                    });
                                }
                                if (dyldFuncLookup == null) {
                                    dyldFuncLookup = emulator.getSvcMemory().registerSvc(new ArmSvc() {
                                        @Override
                                        public long handle(Emulator<?> emulator) {
                                            String name = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0).getString(0);
                                            Pointer address = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                                            return ((Dyld) emulator.getDlfcn())._dyld_func_lookup(emulator, name, address);
                                        }
                                    });
                                }
                                if (dd != null) {
                                    dd.setPointer(0, dyldLazyBinder);
                                    dd.setPointer(emulator.getPointerSize(), dyldFuncLookup);
                                }
                            }
                        }
                    }
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    if ("__DATA".equals(segmentCommand64.segname())) {
                        for (MachO.SegmentCommand64.Section64 section : segmentCommand64.sections()) {
                            if ("__dyld".equals(section.sectName())) {
                                Pointer dd = UnidbgPointer.pointer(emulator, module.base + section.addr());
                                if (dyldLazyBinder == null) {
                                    dyldLazyBinder = emulator.getSvcMemory().registerSvc(new Arm64Svc() {
                                        @Override
                                        public long handle(Emulator<?> emulator) {
                                            return ((Dyld) emulator.getDlfcn())._stub_binding_helper();
                                        }
                                    });
                                }
                                if (dyldFuncLookup == null) {
                                    dyldFuncLookup = emulator.getSvcMemory().registerSvc(new Arm64Svc() {
                                        @Override
                                        public long handle(Emulator<?> emulator) {
                                            String name = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0).getString(0);
                                            Pointer address = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                                            return ((Dyld) emulator.getDlfcn())._dyld_func_lookup(emulator, name, address);
                                        }
                                    });
                                }
                                if (dd != null) {
                                    dd.setPointer(0, dyldLazyBinder);
                                    dd.setPointer(emulator.getPointerSize(), dyldFuncLookup);
                                }
                            }
                        }
                    }
                    break;
            }
        }
    }

    private void bindIndirectSymbolPointers(MachOModule module) {
        if (module.indirectSymbolBound) {
            return;
        }
        module.indirectSymbolBound = true;

        if (module.chainedFixups != null) {
            return;
        }

        MachO.DysymtabCommand dysymtabCommand = module.dysymtabCommand;
        if (dysymtabCommand == null) { // virtual module
            return;
        }

        List<Long> indirectTable = dysymtabCommand.indirectSymbols();
        MachO.DyldInfoCommand dyldInfoCommand = module.dyldInfoCommand;
        if (dyldInfoCommand == null) {
            bindLocalRelocations(module);

            boolean allSymbolBound = true;
            for (MachO.LoadCommand command : module.machO.loadCommands()) {
                switch (command.type()) {
                    case SEGMENT: {
                        MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                        for (MachO.SegmentCommand.Section section : segmentCommand.sections()) {
                            allSymbolBound = processSection(module, indirectTable, allSymbolBound, section.flags(), section.size(), section.addr(), section.reserved1());
                        }
                        break;
                    }
                    case SEGMENT_64: {
                        MachO.SegmentCommand64 segmentCommand = (MachO.SegmentCommand64) command.body();
                        for (MachO.SegmentCommand64.Section64 section : segmentCommand.sections()) {
                            allSymbolBound = processSection(module, indirectTable, allSymbolBound, section.flags(), section.size(), section.addr(), section.reserved1());
                        }
                        break;
                    }
                }
            }

            bindExternalRelocations(module);
        } else {
            if (dyldInfoCommand.bindSize() > 0) {
                ByteBuffer buffer = module.buffer.duplicate();
                buffer.limit((int) (dyldInfoCommand.bindOff() + dyldInfoCommand.bindSize()));
                buffer.position((int) dyldInfoCommand.bindOff());

                Logger log = LoggerFactory.getLogger("com.github.unidbg.ios." + module.name);
                if (!log.isDebugEnabled()) {
                    log = MachOLoader.log;
                }
                eachBind(log, buffer.slice(), module);
            }
        }
    }

    private boolean processSection(MachOModule module, List<Long> indirectTable, boolean allSymbolBound, long flags, long size, long addr, long reserved1) {
        Logger log = LoggerFactory.getLogger("com.github.unidbg.ios." + module.name);
        if (!log.isDebugEnabled()) {
            log = MachOLoader.log;
        }

        long type = flags & SECTION_TYPE;
        long elementCount = size / emulator.getPointerSize();

        if (type != S_NON_LAZY_SYMBOL_POINTERS && type != S_LAZY_SYMBOL_POINTERS) {
            return allSymbolBound;
        }

        long ptrToBind = addr;
        int indirectTableOffset = (int) reserved1;
        for (int i = 0; i < elementCount; i++, ptrToBind += emulator.getPointerSize()) {
            long symbolIndex = indirectTable.get(indirectTableOffset + i);
            if (symbolIndex == INDIRECT_SYMBOL_ABS) {
                continue; // do nothing since already has absolute address
            }
            if (symbolIndex == INDIRECT_SYMBOL_LOCAL) {
                UnidbgPointer pointer = UnidbgPointer.pointer(emulator, ptrToBind + module.base);
                if (pointer == null) {
                    throw new IllegalStateException("pointer is null");
                }
                Pointer newPointer = pointer.getPointer(0);
                if (newPointer == null) {
                    newPointer = UnidbgPointer.pointer(emulator, module.base);
                } else {
                    newPointer = newPointer.share(module.base);
                }
                if (log.isDebugEnabled()) {
                    log.debug("bindIndirectSymbolPointers pointer={}, newPointer={}", pointer, newPointer);
                }
                pointer.setPointer(0, newPointer);
                continue;
            }

            MachOSymbol symbol = module.getSymbolByIndex((int) symbolIndex);
            if (symbol == null) {
                log.warn("bindIndirectSymbolPointers symbol is null");
                allSymbolBound = false;
                continue;
            }

            boolean isWeakRef = (symbol.nlist.desc() & N_WEAK_REF) != 0;
            long address = resolveSymbol(module, symbol);

            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, ptrToBind + module.base);
            if (pointer == null) {
                throw new IllegalStateException("pointer is null");
            }
            if (address == 0L) {
                if (log.isDebugEnabled()) {
                    log.debug("bindIndirectSymbolPointers symbol={}, isWeakRef={}", symbol, isWeakRef);
                }
                pointer.setPointer(0, null);
            } else {
                pointer.setPointer(0, UnidbgPointer.pointer(emulator, address));
                if (log.isDebugEnabled()) {
                    log.debug("bindIndirectSymbolPointers symbolIndex=0x{}, symbol={}, ptrToBind=0x{}", Long.toHexString(symbolIndex), symbol, Long.toHexString(ptrToBind));
                }
            }
        }
        return allSymbolBound;
    }

    private void eachBind(Logger log, ByteBuffer buffer, MachOModule module) {
        final List<MemRegion> regions = module.getRegions();
        int type = 0;
        int segmentIndex;
        long address = module.base;
        long segmentEndAddress = address + module.size;
        String symbolName = null;
        int symbolFlags = 0;
        int libraryOrdinal = 0;
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
                    doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module);
                    address += emulator.getPointerSize();
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module);
                    address += (Utils.readULEB128(buffer).longValue() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                    if (address >= segmentEndAddress) {
                        throw new IllegalStateException();
                    }
                    doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module);
                    address += ((long) immediate *emulator.getPointerSize() + emulator.getPointerSize());
                    break;
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    count = Utils.readULEB128(buffer).intValue();
                    skip = Utils.readULEB128(buffer).intValue();
                    for (int i = 0; i < count; i++) {
                        if (address >= segmentEndAddress) {
                            throw new IllegalStateException();
                        }
                        doBindAt(log, libraryOrdinal, type, address, symbolName, symbolFlags, addend, module);
                        address += (skip + emulator.getPointerSize());
                    }
                    break;
                default:
                    throw new IllegalStateException(String.format("bad bind opcode 0x%s in bind info", Integer.toHexString(opcode)));
            }
        }
    }

    private void doBindAt(Logger log, int libraryOrdinal, int type, long address, String symbolName, int symbolFlags, long addend, MachOModule module) {
        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalStateException();
        }
//        libraryOrdinal = (byte) libraryOrdinal;

        MachOModule targetImage;
        if (libraryOrdinal == BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE) {
            targetImage = executableModule;
        } else if (libraryOrdinal == BIND_SPECIAL_DYLIB_SELF) {
            targetImage = module;
        } else if (libraryOrdinal == BIND_SPECIAL_DYLIB_FLAT_LOOKUP) {
            for(MachOModule mm : modules.values().toArray(new MachOModule[0])) {
                if (doBindAt(type, pointer, addend, module, mm, symbolName, false)) {
                    return;
                }
            }
            module.addNotBoundSymbol(symbolName);
            return;
        } else if (libraryOrdinal <= 0) {
            throw new IllegalStateException(String.format("bad mach-o binary, unknown special library ordinal (%d) too big for symbol %s in %s: symbolFlags=0x%x", libraryOrdinal, symbolName, module.getPath(), symbolFlags));
        } else if (libraryOrdinal <= module.ordinalList.size()) {
            String path = module.ordinalList.get(libraryOrdinal - 1);
            targetImage = this.modules.get(FilenameUtils.getName(path));
            if (targetImage == null) { // LOAD_WEAK_DYLIB
                if (log.isDebugEnabled()) {
                    log.debug("doBindAt LOAD_WEAK_DYLIB: {}", path);
                }
                module.addNotBoundSymbol(symbolName);
                return;
            }
        } else {
            throw new IllegalStateException(String.format("bad mach-o binary, library ordinal (%d) too big (max %d) for symbol %s in %s", libraryOrdinal, module.ordinalList.size(), symbolName, module.getPath()));
        }

        targetImage = fakeTargetImage(targetImage, symbolName);
        doBindAt(type, pointer, addend, module, targetImage, symbolName, true);
    }

    final MachOModule fakeTargetImage(MachOModule targetImage, String symbolName) {
        if ("___NSArray0__".equals(symbolName) ||
                "___NSDictionary0__".equals(symbolName) ||
                "_OBJC_CLASS_$_NSConstantIntegerNumber".equals(symbolName) ||
                "_NSProcessInfoPowerStateDidChangeNotification".equals(symbolName) ||
                "_NSExtensionHostDidEnterBackgroundNotification".equals(symbolName) ||
                "_NSExtensionHostDidBecomeActiveNotification".equals(symbolName)) {
            MachOModule fakeImage = this.modules.get("UIKit");
            if (fakeImage == null) {
                fakeImage = this.modules.get("AppKit");
            }
            if (fakeImage == null) {
                fakeImage = this.modules.get("IOKit");
            }
            if (fakeImage == null) {
                emulator.attach().debug();
                throw new IllegalStateException(String.format("targetImage=%s, symbolName=%s", targetImage, symbolName));
            } else {
                targetImage = fakeImage;
            }
        }
        return targetImage;
    }

    final Symbol findSymbolInternal(MachOModule targetImage, String symbolName) {
        if ("CoreFoundation".equals(targetImage.name)) {
            if ("___kCFBooleanFalse".equals(symbolName) ||
                    "___kCFBooleanTrue".equals(symbolName)) {
                Symbol symbol = targetImage.findSymbolByName(symbolName.substring(2), false);
                if (symbol == null) {
                    throw new IllegalStateException();
                }
                long address = symbol.getAddress();
                Pointer pointer = UnidbgPointer.pointer(emulator, address);
                assert pointer != null;
                long value = pointer.getLong(0);
                return new ExportSymbol(symbolName, value, targetImage, 0, com.github.unidbg.ios.MachO.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE);
            }
        }
        Symbol symbol = targetImage.findSymbolByName(symbolName, false);
        if (symbol != null) {
            return symbol;
        }
        if ("CFNetwork".equals(targetImage.name)) {
            MachOModule foundation = modules.get("Foundation");
            if (foundation != null) {
                symbol = findSymbolInternal(foundation, symbolName);
                if (symbol != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Redirect symbol={}", symbol);
                    }
                }
            }
        }
        return symbol;
    }

    private boolean doBindAt(int type, Pointer pointer, long addend, MachOModule module, MachOModule targetImage, String symbolName, boolean updateNotBoundSymbol) {
        Symbol symbol = this.findSymbolInternal(targetImage, symbolName);
        if (symbol == null) {
            if (log.isDebugEnabled()) {
                log.info("doBindAt type={}, symbolName={}, targetImage={}", type, symbolName, targetImage);
            }
            long bindAt = 0;
            for (HookListener listener : hookListeners) {
                long hook = listener.hook(emulator.getSvcMemory(), module.name, symbolName, HookListener.EACH_BIND);
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
                return true;
            }
            if (updateNotBoundSymbol) {
                module.addNotBoundSymbol(symbolName);
            }
            return false;
        }

        long bindAt = symbol.getAddress() + addend;
        for (HookListener listener : hookListeners) {
            long hook = listener.hook(emulator.getSvcMemory(), symbol.getModuleName(), symbol.getName(), bindAt);
            if (hook > 0) {
                bindAt = hook;
                break;
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("doBindAt 0x={}, type={}, symbolName={}, addend={}, lazy=" + false + ", symbol={}, pointer={}, bindAt=0x{}", Long.toHexString(symbol.getValue()), type, symbol.getModuleName(), addend, symbol, pointer, Long.toHexString(bindAt));
        }

        Pointer newPointer = UnidbgPointer.pointer(emulator, bindAt);
        switch (type) {
            case BIND_TYPE_POINTER:
                pointer.setPointer(0, newPointer);
                break;
            case BIND_TYPE_TEXT_ABSOLUTE32:
                pointer.setInt(0, (int) (symbol.getAddress() + addend));
                break;
            case BIND_TYPE_TEXT_PCREL32:
            default:
                throw new IllegalStateException("bad bind type " + type);
        }
        return true;
    }

    private String maxDylibName;
    private long maxSizeOfDylib;

    private void write_mem(int offset, int size, long begin, ByteBuffer buffer) {
        if (size > 0) {
            buffer.limit(offset + size);
            buffer.position(offset);
            byte[] data = new byte[size];
            buffer.get(data);
            pointer(begin).write(data);
        } else if(size < 0) {
            log.warn("write_mem offset={}, size={}, begin=0x{}", offset, offset, Long.toHexString(begin));
        }
    }

    final Map<String, MachOModule> modules = new LinkedHashMap<>();
    final Map<String, MachOModule> path_modules = new HashMap<>();

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

    private Symbol malloc, free;

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        if (runtime) {
            return MemoryBlockImpl.alloc(this, length);
        } else {
            return MemoryAllocBlock.malloc(emulator, malloc, free, length);
        }
    }

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
        if (this.errno != null) {
            this.errno.setInt(0, errno);
        }
    }

    @Override
    public Module dlopen(String path) {
        return dlopen(path, true);
    }

    private void processBind(MachOModule m) {
        bindIndirectSymbolPointers(m);
        setupLazyPointerHandler(m);
    }

    public boolean dlopen_preflight(String path) {
        MachOModule loaded = modules.get(FilenameUtils.getName(path));
        if (loaded != null) {
            return true;
        }
        LibraryFile libraryFile = libraryResolver == null ? null : libraryResolver.resolveLibrary(emulator, path);
        return libraryFile != null;
    }

    @Override
    public Module dlopen(String path, boolean callInit) {
        if ("/usr/lib/libSystem.dylib".equals(path)) {
            path = "/usr/lib/libSystem.B.dylib";
        }
        MachOModule loadedModule = modules.get(FilenameUtils.getName(path));
        if (loadedModule != null) {
            loadedModule.addReferenceCount();
            return loadedModule;
        }

        for (Module module : getLoadedModules()) {
            for (MemRegion memRegion : module.getRegions()) {
                if (path.equals(memRegion.getName())) {
                    module.addReferenceCount();
                    return module;
                }
            }
        }

        LibraryFile libraryFile = libraryResolver == null ? null : libraryResolver.resolveLibrary(emulator, path);
        if (libraryFile == null) {
            return null;
        }

        MachOModule module = loadInternalPhase(libraryFile, true, false, Collections.emptyList());

        for (MachOModule export : modules.values().toArray(new MachOModule[0])) {
            for (NeedLibrary library : export.lazyLoadNeededList.toArray(new NeedLibrary[0])) {
                String neededLibrary = library.path;
                if (log.isDebugEnabled()) {
                    log.debug("dlopen {} need dependency {}", export.getPath(), neededLibrary);
                }

                MachOModule loaded = modules.get(FilenameUtils.getName(neededLibrary));
                if (loaded != null) {
                    if (library.upward) {
                        export.upwardLibraries.put(FilenameUtils.getBaseName(neededLibrary), loaded);
                    }
                    continue;
                }
                try {
                    LibraryFile neededLibraryFile = resolveLibrary(libraryFile, neededLibrary, Collections.singletonList(FilenameUtils.getFullPath(libraryFile.getPath())));
                    if (neededLibraryFile != null) {
                        MachOModule needed = loadInternalPhase(neededLibraryFile, true, false, Collections.emptySet());
                        needed.addReferenceCount();

                        if (library.upward) {
                            export.upwardLibraries.put(FilenameUtils.getBaseName(needed.name), needed);
                        }
                    } else if (!library.weak) {
                        log.info("{} load dependency {} failed", export.getPath(), neededLibrary);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            export.lazyLoadNeededList.clear();
        }

        for (MachOModule export : modules.values()) {
            if (!export.lazyLoadNeededList.isEmpty()) {
                log.info("dlopen {} resolve needed library failed: {}, neededList={}", path, export.name, export.lazyLoadNeededList);
            }
        }
        for (MachOModule m : modules.values()) {
            processBind(m);
        }

        if (!callInitFunction) { // No need call init array
            for (MachOModule m : modules.values()) {
                m.initFunctionList.clear();
            }
        }

        if (callInit) {
            for (MachOModule m : modules.values()) {
                if (m.symbolNotBound.isEmpty()) {
                    m.doInitialization(emulator);
                }
            }
        }

        module.addReferenceCount();
        return module;
    }

    @Override
    public boolean dlclose(long handle) {
        throw new UnsupportedOperationException();
    }


    @Override
    public Symbol dlsym(long handle, String symbolName) {
        for (MachOModule module : modules.values()) {
            if (module.machHeader == handle) {
                return module.findSymbolByName(symbolName, false);
            }
            if (handle == Dyld.RTLD_NEXT) {
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    return symbol;
                }
            }
        }
        if (handle == Dyld.RTLD_DEFAULT) {
            for (Module module : modules.values()) {
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    return symbol;
                }
            }
        }
        log.info("dlsym failed: handle={}, symbolName={}", handle, symbolName);
        return null;
    }

    @Override
    public Collection<Module> getLoadedModules() {
        return new ArrayList<>(modules.values());
    }

    final List<Module> getLoadedModulesNoVirtual() {
        List<Module> list = new ArrayList<>(modules.size());
        for (MachOModule mm : modules.values()) {
            if (!mm.isVirtual()) {
                list.add(mm);
            }
        }
        return list;
    }

    @Override
    public String getMaxLengthLibraryName() {
        return maxDylibName;
    }

    @Override
    public long getMaxSizeOfLibrary() {
        return maxSizeOfDylib;
    }

    final List<UnidbgPointer> addImageCallbacks = new ArrayList<>();
    final List<UnidbgPointer> boundHandlers = new ArrayList<>();
    final List<UnidbgPointer> initializedHandlers = new ArrayList<>();
    UnidbgPointer _objcNotifyMapped;
    UnidbgPointer _objcNotifyInit;

    private UnidbgStructure createDyldImageInfo(MachOModule module) {
        if (emulator.is64Bit()) {
            int elementSize = UnidbgStructure.calculateSize(DyldImageInfo64.class);
            Pointer pointer = emulator.getSvcMemory().allocate(elementSize, "notifySingle");
            DyldImageInfo64 info = new DyldImageInfo64(pointer);
            info.imageFilePath = UnidbgPointer.nativeValue(module.createPathMemory(emulator.getSvcMemory()));
            info.imageLoadAddress = module.machHeader;
            info.imageFileModDate = 0;
            info.pack();
            return info;
        } else {
            int elementSize = UnidbgStructure.calculateSize(DyldImageInfo32.class);
            Pointer pointer = emulator.getSvcMemory().allocate(elementSize, "notifySingle");
            DyldImageInfo32 info = new DyldImageInfo32(pointer);
            info.imageFilePath = (int) (UnidbgPointer.nativeValue(module.createPathMemory(emulator.getSvcMemory())));
            info.imageLoadAddress = (int) module.machHeader;
            info.imageFileModDate = 0;
            info.pack();
            return info;
        }
    }

    private void notifySingle(int state, MachOModule module) {
        if (module.isVirtual()) { // virtual module
            return;
        }

        UnidbgStructure info = createDyldImageInfo(module);
        switch (state) {
            case Dyld.dyld_image_state_bound:
                long slide = module.slide;
                if (!module.executable) {
                    for (UnidbgPointer callback : addImageCallbacks) {
                        if (module.addImageCallSet.add(callback)) {
                            if (log.isDebugEnabled()) {
                                log.debug("notifySingle callback={}, module={}", callback, module.name);
                            }
                            Module.emulateFunction(emulator, callback.peer, UnidbgPointer.pointer(emulator, module.machHeader), UnidbgPointer.pointer(emulator, slide));
                        }
                    }
                }
                for (UnidbgPointer handler : boundHandlers) {
                    if (module.boundCallSet.add(handler)) {
                        if (log.isDebugEnabled()) {
                            log.debug("notifySingle state={}, handler={}, module={}", state, handler, module.name);
                        }
                        Module.emulateFunction(emulator, handler.peer, state, 1, info);
                    }
                }
                break;
            case Dyld.dyld_image_state_dependents_initialized:
                for (UnidbgPointer handler : initializedHandlers) {
                    if (module.dependentsInitializedCallSet.add(handler)) {
                        if (log.isDebugEnabled()) {
                            log.debug("dyld_image_state_dependents_initialized notifySingle state={}, handler={}, module={}", state, handler, module.name);
                        }
                        Module.emulateFunction(emulator, handler.peer, state, 1, info);
                    }
                }
                break;
            case Dyld.dyld_image_state_initialized:
                for (UnidbgPointer handler : boundHandlers) {
                    if (module.initializedCallSet.add(handler)) {
                        if (log.isDebugEnabled()) {
                            log.debug("dyld_image_state_initialized notifySingle state={}, handler={}, module={}", state, handler, module.name);
                        }
                        Module.emulateFunction(emulator, handler.peer, state, 1, info);
                    }
                }
                module.callObjcNotifyInit(_objcNotifyInit);
                break;
            default:
                throw new UnsupportedOperationException("state=" + state);
        }
    }

    private void setExecuteModule(MachOModule module) {
        if (executableModule == null) {
            executableModule = module;

            vars.setPointer(0, UnidbgPointer.pointer(emulator, module.machHeader)); // _NSGetMachExecuteHeader
        }
    }

    MachOModule executableModule;

    final long allocate(long size, long mask) {
        if (log.isDebugEnabled()) {
            log.debug("allocate size=0x{}, mask=0x{}", Long.toHexString(size), Long.toHexString(mask));
        }

        long address = allocateMapAddress(mask, size);
        int prot = UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE;
        backend.mem_map(address, size, prot);
        if (mMapListener != null) {
            mMapListener.onMap(address, size, prot);
        }
        if (memoryMap.put(address, new MemoryMap(address, size, prot)) != null) {
            log.warn("Replace memory map address=0x{}", Long.toHexString(address));
        }
        return address;
    }

    public Module getExecutableModule() {
        return executableModule;
    }

    final void remap(VmRemapRequest args) {
        MemoryMap memoryMap = null;
        for (MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if (args.target_address >= map.base && args.target_address + args.size <= map.base + map.size) {
                memoryMap = map;
                break;
            }
        }
        if (memoryMap != null) {
            munmap(args.target_address, (int) args.size);
        }
        int prot = UnicornConst.UC_PROT_ALL;
        try {
            backend.mem_map(args.target_address, args.size, prot);
            if (mMapListener != null) {
                mMapListener.onMap(args.target_address, args.size, prot);
            }
        } catch (BackendException e) {
            throw new IllegalStateException("remap target_address=0x" + Long.toHexString(args.target_address) + ", size=" + args.size, e);
        }
        if (this.memoryMap.put(args.target_address, new MemoryMap(args.target_address, args.size, prot)) != null) {
            log.warn("remap replace exists memory map: start={}", Long.toHexString(args.target_address));
        }
    }

    @Override
    public long mmap2(long start, int length, int prot, int flags, int fd, int offset) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());

        boolean isAnonymous = ((flags & com.github.unidbg.ios.MachO.MAP_ANONYMOUS) != 0) || (start == 0 && fd <= 0 && offset == 0);
        if ((flags & MAP_FIXED) != 0 && isAnonymous) {
            if (log.isDebugEnabled()) {
                log.debug("mmap2 MAP_FIXED start=0x{}, length={}, prot={}", Long.toHexString(start), length, prot);
            }

            MemoryMap mapped = null;
            for (MemoryMap map : memoryMap.values()) {
                if (start >= map.base && start + aligned <= map.base + map.size) {
                    mapped = map;
                }
            }

            if (mapped != null) {
                munmap(start, aligned);
                backend.mem_map(start, aligned, prot);
                if (mMapListener != null) {
                    mMapListener.onMap(start, aligned, prot);
                }
                if (memoryMap.put(start, new MemoryMap(start, aligned, prot)) != null) {
                    log.warn("mmap2 replace exists memory map: start={}", Long.toHexString(start));
                }
                return start;
            } else {
                throw new IllegalStateException("mmap2 MAP_FIXED not found mapped memory: start=0x" + Long.toHexString(start));
            }
        }

        if (isAnonymous) {
            long addr = allocateMapAddress(0, aligned);
            if (log.isDebugEnabled()) {
                log.debug("mmap2 addr=0x{}, mmapBaseAddress=0x{}, start={}, fd={}, offset={}, aligned={}", Long.toHexString(addr), Long.toHexString(mmapBaseAddress), start, fd, offset, aligned);
            }
            backend.mem_map(addr, aligned, prot);
            if (mMapListener != null) {
                mMapListener.onMap(addr, aligned, prot);
            }
            if (memoryMap.put(addr, new MemoryMap(addr, aligned, prot)) != null) {
                log.warn("mmap2 replace exists memory map: addr={}", Long.toHexString(addr));
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

            if ((flags & MAP_FIXED) != 0) {
                if (log.isDebugEnabled()) {
                    log.debug("mmap2 MAP_FIXED start=0x{}, length={}, prot={}, fd={}, offset=0x{}", Long.toHexString(start), length, prot, fd, Long.toHexString(offset));
                }

                MemoryMap mapped = null;
                for (MemoryMap map : memoryMap.values()) {
                    if (start >= map.base && start + aligned <= map.base + map.size) {
                        mapped = map;
                    }
                }

                if (mapped != null) {
                    backend.mem_unmap(start, aligned);
                    if (mMapListener != null) {
                        mMapListener.onUnmap(start, aligned);
                    }
                } else {
                    log.warn("mmap2 MAP_FIXED not found mapped memory: start=0x{}", Long.toHexString(start));
                }
                FileIO io = syscallHandler.getFileIO(fd);
                if (io != null) {
                    long ret = io.mmap2(emulator, start, aligned, prot, offset, length);
                    if (mMapListener != null) {
                        mMapListener.onMap(start, aligned, prot);
                    }
                    return ret;
                }
            }
            if (flags == MAP_MY_FIXED) {
                if (log.isDebugEnabled()) {
                    log.debug("mmap2 NOT VM_FLAGS_ANYWHERE start=0x{}, length={}, prot={}, fd={}, offset=0x{}", Long.toHexString(start), length, prot, fd, Long.toHexString(offset));
                }

                MemoryMap mapped = null;
                for (MemoryMap map : memoryMap.values()) {
                    if (start >= map.base && start + aligned <= map.base + map.size) {
                        mapped = map;
                    }
                }

                if (mapped != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("mmap2 NOT VM_FLAGS_ANYWHERE found mapped memory: start=0x{}", Long.toHexString(start));
                    }
                    return 0;
                }
                backend.mem_map(start, aligned, prot);
                if (mMapListener != null) {
                    mMapListener.onMap(start, aligned, prot);
                }
                if (memoryMap.put(start, new MemoryMap(start, aligned, prot)) != null) {
                    log.warn("mmap2 NOT VM_FLAGS_ANYWHERE exists memory map addr=0x{}", Long.toHexString(start));
                }
                if (start + aligned >= mmapBaseAddress) {
                    setMMapBaseAddress(start + aligned);
                }
                return start;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        throw new AbstractMethodError("mmap2 start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset);
    }

    @Override
    public Module loadVirtualModule(String name, Map<String, UnidbgPointer> symbols) {
        MachOModule module = MachOModule.createVirtualModule(name, symbols, emulator);
        modules.put(name, module);
        if (maxDylibName == null || name.length() > maxDylibName.length()) {
            maxDylibName = name;
        }
        return module;
    }

    @Override
    protected long getModuleBase(Module module) {
//        return ((MachOModule) module).machHeader;
        return super.getModuleBase(module);
    }
}
