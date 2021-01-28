package com.github.unidbg.spi;

import com.github.unidbg.*;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.io.DataOutput;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public abstract class AbstractLoader<T extends NewFileIO> implements Memory, Loader {

    private static final Log log = LogFactory.getLog(AbstractLoader.class);

    protected final Backend backend;
    protected final Emulator<T> emulator;
    protected final UnixSyscallHandler<T> syscallHandler;

    protected long sp;
    protected long mmapBaseAddress;
    protected final Map<Long, MemoryMap> memoryMap = new TreeMap<>();

    protected void setMMapBaseAddress(long address) {
        this.mmapBaseAddress = address;

        if (log.isDebugEnabled()) {
            log.debug("setMMapBaseAddress=0x" + Long.toHexString(address));
        }
    }

    public AbstractLoader(Emulator<T> emulator, UnixSyscallHandler<T> syscallHandler) {
        this.backend = emulator.getBackend();
        this.emulator = emulator;
        this.syscallHandler = syscallHandler;

        setMMapBaseAddress(MMAP_BASE);
    }

    @Override
    public Collection<MemoryMap> getMemoryMap() {
        return memoryMap.values();
    }

    @Override
    public final UnidbgPointer mmap(int length, int prot) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());
        long addr = mmap2(0, aligned, prot, 0, -1, 0);
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, addr);
        assert pointer != null;
        return pointer.setSize(aligned);
    }

//    private static final int MAP_SHARED =	0x01;		/* Share changes */
//    private static final int MAP_PRIVATE =	0x02;		/* Changes are private */
//    private static final int MAP_TYPE =	0x0f;		/* Mask for type of mapping */
//    private static final int MAP_FIXED =	0x10;		/* Interpret addr exactly */
//    private static final int MAP_ANONYMOUS =	0x20;		/* don't use a file */

    protected final long allocateMapAddress(long mask, long length) {
        Map.Entry<Long, MemoryMap> lastEntry = null;
        for (Map.Entry<Long, MemoryMap> entry : memoryMap.entrySet()) {
            if (lastEntry == null) {
                lastEntry = entry;
            } else {
                MemoryMap map = lastEntry.getValue();
                long mmapAddress = map.base + map.size;
                if (mmapAddress + length < entry.getKey() && (mmapAddress & mask) == 0) {
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
                setMMapBaseAddress(mmapAddress);
            }
        }

        long addr = mmapBaseAddress;
        while ((addr & mask) != 0) {
            addr += emulator.getPageAlign();
        }
        setMMapBaseAddress(addr + length);
        return addr;
    }

    @Override
    public final int munmap(long start, int length) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());
        backend.mem_unmap(start, aligned);
        MemoryMap removed = memoryMap.remove(start);

        if (removed == null) {
            MemoryMap segment = null;
            for (Map.Entry<Long, MemoryMap> entry : memoryMap.entrySet()) {
                MemoryMap map = entry.getValue();
                if (start > entry.getKey() && start < map.base + map.size) {
                    segment = entry.getValue();
                    break;
                }
            }
            if (segment == null || segment.size < aligned) {
                throw new IllegalStateException("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start));
            }
            if (start + aligned < segment.base + segment.size) {
                long newSize = segment.base + segment.size - start - aligned;
                if (log.isDebugEnabled()) {
                    log.debug("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start) + ", base=0x" + Long.toHexString(start + aligned) + ", size=" + newSize);
                }
                if (memoryMap.put(start + aligned, new MemoryMap(start + aligned, (int) newSize, segment.prot)) != null) {
                    log.warn("munmap replace exists memory map addr=0x" + Long.toHexString(start + aligned));
                }
            }
            if (memoryMap.put(segment.base, new MemoryMap(segment.base, (int) (start - segment.base), segment.prot)) == null) {
                log.warn("munmap replace failed warning: addr=0x" + Long.toHexString(segment.base));
            }
            if (log.isDebugEnabled()) {
                log.debug("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start) + ", base=0x" + Long.toHexString(segment.base) + ", size=" + (start - segment.base));
            }
            return 0;
        }

        if(removed.size != aligned) {
            if (aligned >= removed.size) {
                if (log.isDebugEnabled()) {
                    log.debug("munmap removed=0x" + Long.toHexString(removed.size) + ", aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start));
                }
                long address = start + removed.size;
                long size = aligned - removed.size;
                while (size != 0) {
                    MemoryMap remove = memoryMap.remove(address);
                    address += remove.size;
                    size -= remove.size;
                }
                return 0;
            }

            if (memoryMap.put(start + aligned, new MemoryMap(start + aligned, removed.size - aligned, removed.prot)) != null) {
                log.warn("munmap replace exists memory map addr=0x" + Long.toHexString(start + aligned));
            }
            if (log.isDebugEnabled()) {
                log.debug("munmap removed=0x" + Long.toHexString(removed.size) + ", aligned=0x" + Long.toHexString(aligned) + ", base=0x" + Long.toHexString(start + aligned) + ", size=" + (removed.size - aligned));
            }
            return 0;
        }

        if (log.isDebugEnabled()) {
            log.debug("munmap aligned=0x" + Long.toHexString(aligned) + ", start=0x" + Long.toHexString(start) + ", base=0x" + Long.toHexString(removed.base) + ", size=" + removed.size);
        }
        if (memoryMap.isEmpty()) {
            setMMapBaseAddress(MMAP_BASE);
        }
        return 0;
    }

    @Override
    public final int mprotect(long address, int length, int prot) {
        if (address % ARMEmulator.PAGE_ALIGN != 0) {
            setErrno(UnixEmulator.EINVAL);
            return -1;
        }

        backend.mem_protect(address, length, prot);
        return 0;
    }

    @Override
    public final Module load(File elfFile) {
        return load(elfFile,false);
    }

    @Override
    public final Module load(LibraryFile libraryFile) {
        return load(libraryFile, false);
    }

    @Override
    public final Module load(File elfFile, boolean forceCallInit) {
        return loadInternal(createLibraryFile(elfFile), forceCallInit);
    }

    protected abstract LibraryFile createLibraryFile(File file);

    @Override
    public final Module load(LibraryFile libraryFile, boolean forceCallInit) {
        return loadInternal(libraryFile, forceCallInit);
    }

    protected abstract Module loadInternal(LibraryFile libraryFile, boolean forceCallInit);

    protected boolean callInitFunction = true;

    @Override
    public final void disableCallInitFunction() {
        this.callInitFunction = false;
    }

    protected final List<HookListener> hookListeners = new ArrayList<>();

    @Override
    public final void addHookListener(HookListener listener) {
        hookListeners.add(listener);
    }

    protected LibraryResolver libraryResolver;

    @Override
    public void setLibraryResolver(LibraryResolver libraryResolver) {
        this.libraryResolver = libraryResolver;
    }

    @Override
    public final UnidbgPointer allocateStack(int size) {
        setStackPoint(sp - size);
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, sp);
        assert pointer != null;
        return pointer.setSize(size);
    }

    @Override
    public final UnidbgPointer writeStackString(String str) {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        return writeStackBytes(Arrays.copyOf(data, data.length + 1));
    }

    @Override
    public final UnidbgPointer writeStackBytes(byte[] data) {
        int size = ARM.alignSize(data.length);
        UnidbgPointer pointer = allocateStack(size);
        assert pointer != null;
        pointer.write(0, data, 0, data.length);
        return pointer;
    }

    @Override
    public final UnidbgPointer pointer(long address) {
        return UnidbgPointer.pointer(emulator, address);
    }

    private long stackBase;
    protected int stackSize;

    @Override
    public long getStackBase() {
        return stackBase;
    }

    @Override
    public int getStackSize() {
        return stackSize;
    }

    @Override
    public final void setStackPoint(long sp) {
        if (this.sp == 0) {
            this.stackBase = sp;
        }
        this.sp = sp;
        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_SP, sp);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, sp);
        }
    }

    @Override
    public long getStackPoint() {
        return sp;
    }

    protected final List<ModuleListener> moduleListeners = new ArrayList<>();

    @Override
    public final void addModuleListener(ModuleListener listener) {
        moduleListeners.add(listener);
    }

    protected final void notifyModuleLoaded(Module module) {
        for (ModuleListener listener : moduleListeners) {
            listener.onLoaded(emulator, module);
        }
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

    protected final Alignment mem_map(long address, long size, int prot, String libraryName, long align) {
        Alignment alignment = ARM.align(address, size, align);

        if (log.isDebugEnabled()) {
            log.debug("[" + libraryName + "]0x" + Long.toHexString(alignment.address) + " - 0x" + Long.toHexString(alignment.address + alignment.size) + ", size=0x" + Long.toHexString(alignment.size) + ", prot=" + prot);
        }

        backend.mem_map(alignment.address, alignment.size, prot);
        if (memoryMap.put(alignment.address, new MemoryMap(alignment.address, (int) alignment.size, prot)) != null) {
            log.warn("mem_map replace exists memory map address=" + Long.toHexString(alignment.address));
        }
        return alignment;
    }

    @Override
    public final Module findModuleByAddress(long address) {
        for (Module module : getLoadedModules()) {
            long base = getModuleBase(module);
            if (address >= base && address < base + module.size) {
                return module;
            }
        }
        return null;
    }

    protected long getModuleBase(Module module) {
        return module.base;
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

    @Override
    public Module loadVirtualModule(String name, Map<String, UnidbgPointer> symbols) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void serialize(DataOutput out) throws IOException {
        out.writeLong(sp);
        out.writeLong(mmapBaseAddress);
        out.writeLong(stackBase);
        out.writeLong(stackSize);
        out.writeInt(memoryMap.size());
        for (Map.Entry<Long, MemoryMap> entry : memoryMap.entrySet()) {
            MemoryMap map = entry.getValue();
            out.writeLong(entry.getKey());
            map.serialize(out);
            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, map.base);
            assert pointer != null;
            byte[] data = pointer.getByteArray(0, (int) map.size);
            out.write(data);
        }
    }

}
