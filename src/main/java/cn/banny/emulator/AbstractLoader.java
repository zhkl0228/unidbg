package cn.banny.emulator;

import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.hook.HookListener;
import cn.banny.emulator.linux.LinuxEmulator;
import cn.banny.emulator.linux.android.ElfLibraryFile;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.pointer.UnicornPointer;
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
    protected final AbstractSyscallHandler syscallHandler;

    protected long sp;
    protected long mmapBaseAddress;
    protected final Map<Long, Integer> memoryMap = new TreeMap<>();

    public AbstractLoader(Emulator emulator, AbstractSyscallHandler syscallHandler) {
        this.unicorn = emulator.getUnicorn();
        this.emulator = emulator;
        this.syscallHandler = syscallHandler;

        mmapBaseAddress = MMAP_BASE;
    }

    @Override
    public final UnicornPointer mmap(int length, int prot) {
        int aligned = (int) ARM.alignSize(length, emulator.getPageAlign());
        UnicornPointer pointer = UnicornPointer.pointer(emulator, mmap2(0, aligned, prot, 0, -1, 0) & 0xffffffffL);
        assert pointer != null;
        return pointer.setSize(aligned);
    }

    @Override
    public final int munmap(long start, int length) {
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
    public final int mprotect(long address, int length, int prot) {
        if (address % ARMEmulator.PAGE_ALIGN != 0) {
            setErrno(LinuxEmulator.EINVAL);
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

}
