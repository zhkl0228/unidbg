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
import java.util.ArrayList;
import java.util.List;
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

    private int allocateSlot() {
        for (int i = slotIndex; i < slots.length; i++) {
            if (slots[i] == null) {
                return i;
            }
        }
        throw new BackendException("Allocate slot failed: slotIndex=" + slotIndex + ", maxSlots=" + slots.length);
    }

    @Override
    public final void mem_map(long address, long size, int perms) throws BackendException {
        int slot = allocateSlot();
        long userspace_addr = kvm.set_user_memory_region(slot, address, size, 0L);
        if (log.isDebugEnabled()) {
            log.debug("mem_map slot=" + slot + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", userspace_addr=0x" + Long.toHexString(userspace_addr));
        }
        UserMemoryRegion region = new UserMemoryRegion(slot, address, size, userspace_addr);
        memoryRegionMap.put(region.guest_phys_addr, region);
        slots[slot++] = region;
        slotIndex = slot;
    }

    @Override
    public final void mem_unmap(long address, long size) throws BackendException {
        List<UserMemoryRegion> list = new ArrayList<>();
        for (UserMemoryRegion region : memoryRegionMap.values()) {
            long min = Math.max(address, region.guest_phys_addr);
            long max = Math.min(address + size, region.guest_phys_addr + region.memory_size);
            if (min < max) {
                list.add(region);
            }
        }
        if (list.size() == 1) {
            UserMemoryRegion region = list.get(0);
            if (address == region.guest_phys_addr && size == region.memory_size) {
                kvm.remove_user_memory_region(region.slot, region.guest_phys_addr, region.memory_size, region.userspace_addr, 0x0);
                slotIndex = region.slot;
                slots[slotIndex] = null;
                memoryRegionMap.remove(region.guest_phys_addr);
                return;
            }
            if (address == region.guest_phys_addr && size < region.memory_size) {
                kvm.remove_user_memory_region(region.slot, region.guest_phys_addr, size, region.userspace_addr, 0x0);
                memoryRegionMap.remove(region.guest_phys_addr);

                long userspace_addr = kvm.set_user_memory_region(region.slot, region.guest_phys_addr + size, region.memory_size - size, region.userspace_addr + size);
                UserMemoryRegion newRegion = new UserMemoryRegion(region.slot, region.guest_phys_addr + size, region.memory_size - size, userspace_addr);
                memoryRegionMap.put(newRegion.guest_phys_addr, newRegion);
                slots[newRegion.slot] = newRegion;
                return;
            }
            if (address > region.guest_phys_addr && address + size == region.guest_phys_addr + region.memory_size) {
                long off = address - region.guest_phys_addr;
                kvm.remove_user_memory_region(region.slot, region.guest_phys_addr, size, region.userspace_addr, off);
                memoryRegionMap.remove(region.guest_phys_addr);

                long userspace_addr = kvm.set_user_memory_region(region.slot, region.guest_phys_addr, region.memory_size - size, region.userspace_addr);
                UserMemoryRegion newRegion = new UserMemoryRegion(region.slot, region.guest_phys_addr, region.memory_size - size, userspace_addr);
                memoryRegionMap.put(newRegion.guest_phys_addr, newRegion);
                slots[newRegion.slot] = newRegion;
                return;
            }
        }
        throw new UnsupportedOperationException("address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", list=" + list);
    }

    @Override
    public final void mem_write(long address, byte[] bytes) throws BackendException {
        try {
            kvm.mem_write(address, bytes);
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
    public final synchronized void emu_start(long begin, long until, long timeout, long count) throws BackendException {
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
