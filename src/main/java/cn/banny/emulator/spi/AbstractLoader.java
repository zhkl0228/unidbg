package cn.banny.emulator.spi;

import cn.banny.emulator.*;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.hook.HookListener;
import cn.banny.emulator.memory.MemoryMap;
import cn.banny.emulator.unix.UnixEmulator;
import cn.banny.emulator.linux.android.ElfLibraryFile;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.WriteHook;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public abstract class AbstractLoader implements Memory, Loader {

    private static final Log log = LogFactory.getLog(AbstractLoader.class);

    protected final Unicorn unicorn;
    protected final Emulator emulator;
    protected final UnixSyscallHandler syscallHandler;

    protected long sp;
    protected long mmapBaseAddress;
    private final Map<Long, MemoryMap> memoryMap = new TreeMap<>();

    public AbstractLoader(Emulator emulator, UnixSyscallHandler syscallHandler) {
        this.unicorn = emulator.getUnicorn();
        this.emulator = emulator;
        this.syscallHandler = syscallHandler;

        mmapBaseAddress = MMAP_BASE;
    }

    @Override
    public Collection<MemoryMap> getMemoryMap() {
        return memoryMap.values();
    }

    @Override
    public final UnicornPointer mmap(int length, int prot) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());
        UnicornPointer pointer = UnicornPointer.pointer(emulator, mmap2(0, aligned, prot, 0, -1, 0) & 0xffffffffL);
        assert pointer != null;
        return pointer.setSize(aligned);
    }

//    private static final int MAP_SHARED =	0x01;		/* Share changes */
//    private static final int MAP_PRIVATE =	0x02;		/* Changes are private */
//    private static final int MAP_TYPE =	0x0f;		/* Mask for type of mapping */
//    private static final int MAP_FIXED =	0x10;		/* Interpret addr exactly */
//    private static final int MAP_ANONYMOUS =	0x20;		/* don't use a file */

    private long allocateMapAddress(int length) {
        Map.Entry<Long, MemoryMap> lastEntry = null;
        for (Map.Entry<Long, MemoryMap> entry : memoryMap.entrySet()) {
            if (lastEntry == null) {
                lastEntry = entry;
            } else {
                MemoryMap map = lastEntry.getValue();
                long mmapAddress = map.base + map.size;
                if (mmapAddress + length <= entry.getKey()) {
                    return mmapAddress;
                } else {
                    lastEntry = entry;
                }
            }
        }
        if (lastEntry != null) {
            MemoryMap map = lastEntry.getValue();
            long mmapAddress = map.base + map.size;
            if (mmapAddress < mmapBaseAddress) {
                log.debug("allocateMapAddress mmapBaseAddress=0x" + Long.toHexString(mmapBaseAddress) + ", mmapAddress=0x" + Long.toHexString(mmapAddress));
                mmapBaseAddress = mmapAddress;
            }
        }

        long addr = mmapBaseAddress;
        mmapBaseAddress += length;
        return addr;
    }

    private static final int MAP_ANONYMOUS = 0x20;

    @Override
    public final int mmap2(long start, int length, int prot, int flags, int fd, int offset) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());

        if (((flags & MAP_ANONYMOUS) != 0) || (start == 0 && fd == -1 && offset == 0)) {
            long addr = allocateMapAddress(aligned);
            log.debug("mmap2 addr=0x" + Long.toHexString(addr) + ", mmapBaseAddress=0x" + Long.toHexString(mmapBaseAddress) + ", start=" + start + ", fd=" + fd + ", offset=" + offset + ", aligned=" + aligned);
            unicorn.mem_map(addr, aligned, prot);
            memoryMap.put(addr, new MemoryMap(addr, aligned, prot));
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
    public final int munmap(long start, int length) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());
        unicorn.mem_unmap(start, aligned);
        MemoryMap removed = memoryMap.remove(start);

        if (removed == null) {
            Map.Entry<Long, MemoryMap> segment = null;
            for (Map.Entry<Long, MemoryMap> entry : memoryMap.entrySet()) {
                MemoryMap map = entry.getValue();
                if (start > entry.getKey() && start < map.base + map.size) {
                    segment = entry;
                    break;
                }
            }
            if (segment == null || segment.getValue().size < aligned) {
                throw new IllegalStateException("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start));
            }

            memoryMap.put(segment.getKey(), new MemoryMap(segment.getKey(), (int) (start - segment.getKey()), segment.getValue().prot));
            log.debug("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start) + ", base=0x" + Long.toHexString(segment.getKey()) + ", size=" + (start - segment.getKey()));
            if (start + aligned < segment.getKey() + segment.getValue().size) {
                log.debug("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start) + ", base=0x" + Long.toHexString(start + aligned) + ", size=" + (segment.getKey() + segment.getValue().size - start - aligned));
                memoryMap.put(start + aligned, new MemoryMap(start + aligned, (int) (segment.getKey() + segment.getValue().size - start - aligned), segment.getValue().prot));
            }

            return 0;
        }

        if(removed.size != aligned) {
            if (aligned >= removed.size) {
                throw new IllegalStateException("munmap removed=0x" + Long.toHexString(removed.size) + ", aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start));
            }

            memoryMap.put(start + aligned, new MemoryMap(start + aligned, removed.size - aligned, removed.prot));
            log.debug("munmap removed=0x" + Long.toHexString(removed.size) + ", aligned=0x" + Long.toHexString(aligned) + ", base=0x" + Long.toHexString(start + aligned) + ", size=" + (removed.size - aligned));
            return 0;
        }
        return 0;
    }

    @Override
    public final int mprotect(long address, int length, int prot) {
        if (address % ARMEmulator.PAGE_ALIGN != 0) {
            setErrno(UnixEmulator.EINVAL);
            return -1;
        }

        unicorn.mem_protect(address, length, prot);
        return 0;
    }

    @Override
    public final Module load(File elfFile) throws IOException {
        return load(elfFile,false);
    }

    @Override
    public final Module load(LibraryFile libraryFile) throws IOException {
        return load(libraryFile, false);
    }

    @Override
    public final Module load(File elfFile, boolean forceCallInit) throws IOException {
        return loadInternal(new ElfLibraryFile(elfFile), null, forceCallInit);
    }

    @Override
    public final Module load(LibraryFile libraryFile, boolean forceCallInit) throws IOException {
        return loadInternal(libraryFile, null, forceCallInit);
    }

    protected abstract Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook, boolean forceCallInit) throws IOException;

    protected boolean callInitFunction;

    @Override
    public final void setCallInitFunction() {
        this.callInitFunction = true;
    }

    protected final List<HookListener> hookListeners = new ArrayList<>();

    @Override
    public final void addHookListener(HookListener listener) {
        hookListeners.add(listener);
    }

    protected LibraryResolver libraryResolver;

    @Override
    public final void setLibraryResolver(LibraryResolver libraryResolver) {
        this.libraryResolver = libraryResolver;

        syscallHandler.addIOResolver(libraryResolver);

        /*
         * 注意打开顺序很重要
         */
        syscallHandler.open(emulator, STDIN, FileIO.O_RDONLY);
        syscallHandler.open(emulator, STDOUT, FileIO.O_WRONLY);
        syscallHandler.open(emulator, STDERR, FileIO.O_WRONLY);
    }

    @Override
    public final UnicornPointer allocateStack(int size) {
        setStackPoint(sp - size);
        UnicornPointer pointer = UnicornPointer.pointer(emulator, sp);
        assert pointer != null;
        return pointer.setSize(size);
    }

    @Override
    public final UnicornPointer writeStackString(String str) {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        return writeStackBytes(Arrays.copyOf(data, data.length + 1));
    }

    @Override
    public final UnicornPointer writeStackBytes(byte[] data) {
        int size = ARM.alignSize(data.length);
        UnicornPointer pointer = allocateStack(size);
        assert pointer != null;
        pointer.write(0, data, 0, data.length);
        return pointer;
    }

    @Override
    public final UnicornPointer pointer(long address) {
        return UnicornPointer.pointer(emulator, address);
    }

    @Override
    public final void setStackPoint(long sp) {
        this.sp = sp;
        if (emulator.getPointerSize() == 4) {
            unicorn.reg_write(ArmConst.UC_ARM_REG_SP, sp);
        } else {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_SP, sp);
        }
    }

    protected ModuleListener moduleListener;

    @Override
    public final void setModuleListener(ModuleListener listener) {
        moduleListener = listener;
    }

    @Override
    public final File dumpStack() throws IOException {
        UnicornPointer sp = UnicornPointer.register(emulator, emulator.getPointerSize() == 4 ? ArmConst.UC_ARM_REG_SP : Arm64Const.UC_ARM64_REG_SP);
        File outFile = File.createTempFile("stack_0x" + Long.toHexString(sp.peer) + "_", ".dat");
        dump(sp, STACK_BASE - sp.peer, outFile);
        return outFile;
    }

    protected final void dump(Pointer pointer, long size, File outFile) throws IOException {
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
    public final MemoryBlock malloc(int length) {
        return malloc(length, true);
    }

    protected final Alignment mem_map(long address, long size, int prot, String libraryName) {
        Alignment alignment = emulator.align(address, size);

        log.debug("[" + libraryName + "]0x" + Long.toHexString(alignment.address) + " - 0x" + Long.toHexString(alignment.address + alignment.size) + ", size=0x" + Long.toHexString(alignment.size));

        unicorn.mem_map(alignment.address, alignment.size, prot);
        memoryMap.put(alignment.address, new MemoryMap(alignment.address, (int) alignment.size, prot));
        return alignment;
    }

    @Override
    public final Module findModuleByAddress(long address) {
        for (Module module : getLoadedModules()) {
            if (address >= module.base && address < module.base + module.size) {
                return module;
            }
        }
        return null;
    }

    @Override
    public final Module findModule(String soName) {
        for (Module module : getLoadedModules()) {
            if (module.name.equals(soName)) {
                return module;
            }
        }
        return null;
    }

}
