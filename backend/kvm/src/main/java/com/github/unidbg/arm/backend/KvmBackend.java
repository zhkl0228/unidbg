package com.github.unidbg.arm.backend;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.kvm.Kvm;
import com.github.unidbg.arm.backend.kvm.KvmCallback;
import com.github.unidbg.arm.backend.kvm.KvmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.TreeMap;

public abstract class KvmBackend extends FastBackend implements Backend, KvmCallback {

    private static final Logger log = LoggerFactory.getLogger(KvmBackend.class);

    protected static final long REG_VBAR_EL1 = 0xf0000000L;

    protected final Kvm kvm;
    private final int pageSize;

    private int slotIndex;
    private final UserMemoryRegion[] slots;
    protected final Map<Long, UserMemoryRegion> memoryRegionMap; // key is guest_phys_addr

    protected KvmBackend(Emulator<?> emulator, Kvm kvm) throws BackendException {
        super(emulator);
        this.kvm = kvm;
        this.pageSize = Kvm.getPageSize();

        int maxSlots = kvm.getMaxSlots();
        if (log.isDebugEnabled()) {
            log.debug("init kvm backend kvm={}, maxSlots=0x{}, pageSize=0x{}", kvm, Integer.toHexString(maxSlots), Integer.toHexString(pageSize));
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
    public void mem_map(long address, long size, int perms) throws BackendException {
        if ((address & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_map address=0x" + Long.toHexString(address));
        }
        if ((size & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_map size=0x" + Long.toHexString(size));
        }

//        System.out.println("mem_map address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size));

        int slot = allocateSlot();
        long userspace_addr = kvm.set_user_memory_region(slot, address, size, 0L);
        if (log.isDebugEnabled()) {
            log.debug("mem_map slot={}, address=0x{}, size=0x{}, userspace_addr=0x{}", slot, Long.toHexString(address), Long.toHexString(size), Long.toHexString(userspace_addr));
        }
        UserMemoryRegion region = new UserMemoryRegion(slot, address, size, userspace_addr);
        memoryRegionMap.put(region.guest_phys_addr, region);
        slots[slot++] = region;
        slotIndex = slot;
    }

    private void mem_unmap_page(long address, UserMemoryRegion region) {
        if (pageSize == region.memory_size) { // page size region
            if (address != region.guest_phys_addr) {
                throw new IllegalStateException("address=0x" + Long.toHexString(address) + ", guest_phys_addr=0x" + Long.toHexString(region.guest_phys_addr));
            }

            kvm.remove_user_memory_region(region.slot, region.guest_phys_addr, region.memory_size, region.userspace_addr, 0x0);
            slotIndex = region.slot;
            slots[slotIndex] = null;
            memoryRegionMap.remove(region.guest_phys_addr);
            return;
        }
        if (address == region.guest_phys_addr && pageSize < region.memory_size) { // region first page
            kvm.remove_user_memory_region(region.slot, region.guest_phys_addr, pageSize, region.userspace_addr, 0x0);
            memoryRegionMap.remove(region.guest_phys_addr);

            long userspace_addr = kvm.set_user_memory_region(region.slot, region.guest_phys_addr + pageSize, region.memory_size - pageSize, region.userspace_addr + pageSize);
            UserMemoryRegion newRegion = new UserMemoryRegion(region.slot, region.guest_phys_addr + pageSize, region.memory_size - pageSize, userspace_addr);
            memoryRegionMap.put(newRegion.guest_phys_addr, newRegion);
            slots[newRegion.slot] = newRegion;
            return;
        }
        if (address > region.guest_phys_addr && address + pageSize == region.guest_phys_addr + region.memory_size) { // region last page
            long off = address - region.guest_phys_addr;
            kvm.remove_user_memory_region(region.slot, region.guest_phys_addr, pageSize, region.userspace_addr, off);
            memoryRegionMap.remove(region.guest_phys_addr);

            long userspace_addr = kvm.set_user_memory_region(region.slot, region.guest_phys_addr, region.memory_size - pageSize, region.userspace_addr);
            UserMemoryRegion newRegion = new UserMemoryRegion(region.slot, region.guest_phys_addr, region.memory_size - pageSize, userspace_addr);
            memoryRegionMap.put(newRegion.guest_phys_addr, newRegion);
            slots[newRegion.slot] = newRegion;
            return;
        }

        // region middle page
        if (address > region.guest_phys_addr && address + pageSize < region.guest_phys_addr + region.memory_size) { // split region
            kvm.remove_user_memory_region(region.slot, region.guest_phys_addr, 0, region.userspace_addr, 0);
            memoryRegionMap.remove(region.guest_phys_addr);

            long first_memory_size = address - region.guest_phys_addr;
            long second_memory_size = region.memory_size - first_memory_size;
            long first_guest_phys_addr = region.guest_phys_addr;

            long first_userspace_addr = kvm.set_user_memory_region(region.slot, first_guest_phys_addr, first_memory_size, region.userspace_addr);

            UserMemoryRegion first = new UserMemoryRegion(region.slot, first_guest_phys_addr, first_memory_size, first_userspace_addr);
            memoryRegionMap.put(first.guest_phys_addr, first);
            slots[first.slot] = first;

            int slot = allocateSlot();
            long second_userspace_addr = kvm.set_user_memory_region(slot, address, second_memory_size, first_userspace_addr + first_memory_size);
            UserMemoryRegion second = new UserMemoryRegion(slot, address, second_memory_size, second_userspace_addr);
            memoryRegionMap.put(second.guest_phys_addr, second);
            slots[slot++] = second;
            slotIndex = slot;

            mem_unmap(address, pageSize);
            return;
        }

        throw new UnsupportedOperationException("address=0x" + Long.toHexString(address));
    }

    @Override
    public final void mem_unmap(long address, long size) throws BackendException {
        if ((address & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_unmap address=0x" + Long.toHexString(address));
        }
        if ((size & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_unmap size=0x" + Long.toHexString(size));
        }

//        System.out.println("mem_unmap address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size));

        for (long i = address; i < address + size; i += pageSize) {
            UserMemoryRegion userMemoryRegion = findUserMemoryRegion(i);

            mem_unmap_page(i, userMemoryRegion);
        }
    }

    private UserMemoryRegion findUserMemoryRegion(long i) {
        UserMemoryRegion userMemoryRegion = null;
        for (UserMemoryRegion region : memoryRegionMap.values()) {
            long min = Math.max(i, region.guest_phys_addr);
            long max = Math.min(i + pageSize, region.guest_phys_addr + region.memory_size);
            if (min < max) {
                userMemoryRegion = region;
                break;
            }
        }
        if (userMemoryRegion == null) {
            throw new IllegalStateException("find userMemoryRegion failed: i=0x" + Long.toHexString(i));
        }
        return userMemoryRegion;
    }

    @Override
    public final void mem_protect(long address, long size, int perms) throws BackendException {
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
            log.debug("callSVC pc=0x{}, until=0x{}, swi={}", Long.toHexString(pc), Long.toHexString(until), swi);
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
            log.debug("emu_start begin=0x{}, until=0x{}, timeout={}, count={}", Long.toHexString(begin), Long.toHexString(until), timeout, count);
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
    public void destroy() throws BackendException {
        IOUtils.close(kvm);
    }

    @Override
    public void hook_add_new(EventMemHook callback, int type, Object user_data) throws BackendException {
    }

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void context_restore(long context) { kvm.context_restore(context); }

    @Override
    public void context_free(long context) {
        Kvm.free(context);
    }

    @Override
    public void context_save(long context) {kvm.context_save(context);}

    @Override
    public long context_alloc() {
        return kvm.context_alloc();
    }


}
