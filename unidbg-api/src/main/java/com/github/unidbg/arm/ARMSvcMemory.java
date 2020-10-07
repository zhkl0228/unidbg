package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.UnicornConst;

import java.io.DataOutput;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ARMSvcMemory implements SvcMemory {

    private static final Log log = LogFactory.getLog(ARMSvcMemory.class);

    private final Emulator<?> emulator;
    private UnidbgPointer base;

    public ARMSvcMemory(long base, int size, Emulator<?> emulator) {
        this.emulator = emulator;
        this.base = UnidbgPointer.pointer(emulator, base);
        assert this.base != null;
        this.base.setSize(size);

        this.baseAddr = base;
        this.size = size;

        Backend backend = emulator.getBackend();
        backend.mem_map(base, size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
    }

    @Override
    public void serialize(DataOutput out) {
        throw new UnsupportedOperationException();
    }

    private final long baseAddr;
    private final int size;

    @Override
    public long getBase() {
        return baseAddr;
    }

    @Override
    public int getSize() {
        return size;
    }

    private final List<MemRegion> memRegions = new ArrayList<>();

    @Override
    public MemRegion findRegion(long addr) {
        for (MemRegion region : memRegions) {
            if (addr >= region.begin && addr < region.end) {
                return region;
            }
        }
        return null;
    }

    @Override
    public UnidbgPointer allocate(int size, final String label) {
        size = ARM.alignSize(size);
        UnidbgPointer pointer = base.share(0, size);
        base = (UnidbgPointer) base.share(size);
        if (log.isDebugEnabled()) {
            log.debug("allocate size=" + size + ", label=" + label + ", base=" + base);
        }
        memRegions.add(new MemRegion(pointer.peer, pointer.peer + size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC, null, 0) {
            @Override
            public String getName() {
                return label;
            }
        });
        return pointer;
    }

    private int thumbSvcNumber = 0;
    private int armSvcNumber = 0xff;

    private final Map<Integer, Svc> svcMap = new HashMap<>();

    @Override
    public Svc getSvc(int svcNumber) {
        return svcMap.get(svcNumber);
    }

    @Override
    public UnidbgPointer registerSvc(Svc svc) {
        final int number;
        if (svc instanceof ThumbSvc) {
            if (emulator.is64Bit()) {
                throw new IllegalStateException("is 64 bit mode");
            }

            if (++thumbSvcNumber == SyscallHandler.DARWIN_SWI_SYSCALL) {
                thumbSvcNumber++;
            }
            number = thumbSvcNumber;
        } else if (svc instanceof ArmSvc || svc instanceof Arm64Svc) {
            if (svc instanceof ArmSvc && emulator.is64Bit()) {
                throw new IllegalStateException("is 64 bit mode");
            }
            if (svc instanceof Arm64Svc && !emulator.is64Bit()) {
                throw new IllegalStateException("is 32 bit mode");
            }

            if (++armSvcNumber == SyscallHandler.DARWIN_SWI_SYSCALL) {
                armSvcNumber++;
            }
            number = armSvcNumber;
        } else {
            throw new IllegalStateException("svc=" + svc);
        }
        if (svcMap.put(number, svc) != null) {
            throw new IllegalStateException();
        }
        return svc.onRegister(this, number);
    }

    @Override
    public final UnidbgPointer writeStackString(String str) {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        return writeStackBytes(Arrays.copyOf(data, data.length + 1));
    }

    @Override
    public final UnidbgPointer writeStackBytes(byte[] data) {
        UnidbgPointer pointer = allocate(data.length, "writeStackBytes: " + Hex.encodeHexString(data));
        assert pointer != null;
        pointer.write(0, data, 0, data.length);
        return pointer;
    }

}
