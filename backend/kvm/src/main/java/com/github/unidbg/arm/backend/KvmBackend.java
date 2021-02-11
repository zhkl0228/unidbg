package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.kvm.Kvm;
import com.github.unidbg.arm.backend.kvm.KvmCallback;
import com.github.unidbg.arm.backend.kvm.KvmException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;
import java.util.TreeMap;

public abstract class KvmBackend extends FastBackend implements Backend, KvmCallback {

    private static final Log log = LogFactory.getLog(KvmBackend.class);

    protected final Kvm kvm;
    private final int pageSize;

    private int slotIndex;
    private final UserMemoryRegion[] slots;
    protected final Map<Long, UserMemoryRegion> memoryRegionMap; // key is guest_phys_addr

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
            kvm.mem_write(address, bytes);
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
