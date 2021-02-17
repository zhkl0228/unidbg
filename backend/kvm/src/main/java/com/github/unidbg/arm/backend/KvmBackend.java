package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.kvm.Kvm;
import com.github.unidbg.arm.backend.kvm.KvmCallback;
import com.github.unidbg.arm.backend.kvm.KvmException;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.TreeMap;

public abstract class KvmBackend extends FastBackend implements Backend, KvmCallback {

    private static final Log log = LogFactory.getLog(KvmBackend.class);

    protected static final long REG_VBAR_EL1 = 0xf0000000L;

    protected final Kvm kvm;
    private final int pageSize;

    private int slotIndex;
    private final UserMemoryRegion[] slots;
    protected final Map<Long, UserMemoryRegion> memoryRegionMap; // key is guest_phys_addr

    @Override
    public void onInitialize() {
        super.onInitialize();

        mem_map(REG_VBAR_EL1, getPageSize(), UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        ByteBuffer buffer = ByteBuffer.allocate(getPageSize());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            if (buffer.position() == 0x400) {
                buffer.putInt(0x390003e0); // strb w0, [sp]
            } else {
                buffer.putInt(0x390003e1); // strb w1, [sp]
            }
            if (buffer.hasRemaining()) {
                buffer.putInt(0xd69f03e0); // eret
            }
        }
        UnidbgPointer ptr = UnidbgPointer.pointer(emulator, REG_VBAR_EL1);
        assert ptr != null;
        ptr.write(buffer.array());

        mem_map(0, getPageSize(), UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        buffer = ByteBuffer.allocate(getPageSize());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            buffer.putInt(0xd4211100); // brk #0x888
        }
        mem_write(0, buffer.array());
    }

    private int allocateSlot() {
        for (int i = slotIndex; i < slots.length; i++) {
            if (slots[i] == null) {
                return i;
            }
        }
        throw new BackendException("Allocate slot failed: slotIndex=" + slotIndex + ", maxSlots=" + slots.length);
    }

    protected KvmBackend(Emulator<?> emulator, Kvm kvm) throws BackendException {
        super(emulator);
        this.kvm = kvm;
        this.pageSize = Kvm.getPageSize();

        int maxSlots = Kvm.getMaxSlots();
        if (log.isDebugEnabled()) {
            log.debug("init kvm backend kvm=" + kvm + ", maxSlots=0x" + Integer.toHexString(maxSlots) + ", pageSize=0x" + Integer.toHexString(pageSize));
        }

        this.slots = new UserMemoryRegion[maxSlots];
        this.memoryRegionMap = new TreeMap<>();
        try {
            this.kvm.setKvmCallback(this);
        } catch (KvmException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public final void mem_map(long address, long size, int perms) throws BackendException {
        int slot = allocateSlot();
        long userspace_addr = kvm.set_user_memory_region(slot, address, size);
        if (log.isDebugEnabled()) {
            log.debug("mem_map slot=" + slot + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", userspace_addr=0x" + Long.toHexString(userspace_addr));
        }
        UserMemoryRegion region = new UserMemoryRegion(slot, address, size, userspace_addr);
        memoryRegionMap.put(address, region);
        slots[slot++] = region;
        slotIndex = slot;
    }

    @Override
    public final void mem_write(long address, byte[] bytes) throws BackendException {
        try {
            if (address < 0x40a3aaac && address + bytes.length >= 0x40a3aaac + 4) {
                long addr = 0x40a3aaac;
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt((int) (addr - address), 0x90000002); // adrp x2, #0
                buffer.putInt((int) (addr - address) + 4, 0xf9400041); // ldr x1, [x2]
                buffer.putInt((int) (addr - address) + 8, 0xd400aaa1); // svc #0x555
            }
            if (address < 0x40a3aa98 && address + bytes.length >= 0x40a3aa98 + 4) {
                long addr = 0x40a3aa98;
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt((int) (addr - address), 0x90000002); // adrp x2, #0
                buffer.putInt((int) (addr - address) + 4, 0xf9400041); // ldr x1, [x2]
                buffer.putInt((int) (addr - address) + 8, 0xd400aaa1); // svc #0x555
            }

            kvm.mem_write(address, bytes);

            if (address < 0x40a3aaac && address + bytes.length >= 0x40a3aaac + 4) {
                long addr = 0x40a3aaac;
                emulator.attach().disassembleBlock(emulator, addr, false);
            }
            if (address < 0x40a3aa98 && address + bytes.length >= 0x40a3aa98 + 4) {
                long addr = 0x40a3aa98;
                emulator.attach().disassembleBlock(emulator, addr, false);
            }
        } catch (KvmException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public final byte[] mem_read(long address, long size) throws BackendException {
        try {
            return kvm.mem_read(address, (int) size);
        } catch (KvmException e) {
            throw new BackendException(e);
        }
    }

    protected final void callSVC(long pc, int swi) {
        if (log.isDebugEnabled()) {
            log.debug("callSVC pc=0x" + Long.toHexString(pc) + ", until=0x" + Long.toHexString(until) + ", swi=" + swi);
        }
        if (pc == until) {
            emu_stop();
            return;
        }
        interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_SWI, swi);
    }

    protected InterruptHookNotifier interruptHookNotifier;

    @Override
    public final void hook_add_new(InterruptHook callback, Object user_data) throws BackendException {
        if (interruptHookNotifier != null) {
            throw new IllegalStateException();
        } else {
            interruptHookNotifier = new InterruptHookNotifier(callback, user_data);
        }
    }

    protected long until;

    @Override
    public synchronized void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        if (log.isDebugEnabled()) {
            log.debug("emu_start begin=0x" + Long.toHexString(begin) + ", until=0x" + Long.toHexString(until) + ", timeout=" + timeout + ", count=" + count);
        }

        this.until = until + 4;
        try {
            kvm.emu_start(begin);
        } catch (KvmException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public final void emu_stop() throws BackendException {
        try {
            kvm.emu_stop();
        } catch (KvmException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public int getPageSize() {
        return pageSize;
    }

    @Override
    public final void destroy() throws BackendException {
        IOUtils.closeQuietly(kvm);
    }

    @Override
    public void hook_add_new(EventMemHook callback, int type, Object user_data) throws BackendException {
    }

    @Override
    public void context_restore(long context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void context_save(long context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long context_alloc() {
        throw new UnsupportedOperationException();
    }

}
