package com.github.unidbg.arm.backend;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class UserMemoryRegionTest extends TestCase {

    private int pageSize;

    protected Map<Long, UserMemoryRegion> memoryRegionMap;
    private int slotIndex;
    private UserMemoryRegion[] slots;

    private int allocateSlot() {
        for (int i = slotIndex; i < slots.length; i++) {
            if (slots[i] == null) {
                return i;
            }
        }
        throw new BackendException("Allocate slot failed: slotIndex=" + slotIndex + ", maxSlots=" + slots.length);
    }

    private long set_user_memory_region(int slot, long guest_phys_addr, long memory_size, long old_addr) {
        System.out.println("set_user_memory_region slot=" + slot + ", guest_phys_addr=0x" + Long.toHexString(guest_phys_addr) +
                ", memory_size=0x" + Long.toHexString(memory_size) + ", old_addr=0x" + Long.toHexString(old_addr));
        return guest_phys_addr;
    }

    private void remove_user_memory_region(int slot, long guest_phys_addr, long memory_size, long userspace_addr, long vaddr_off) {
        System.out.println("remove_user_memory_region slot=" + slot + ", guest_phys_addr=0x" + Long.toHexString(guest_phys_addr) +
                ", memory_size=0x" + Long.toHexString(memory_size) + ", userspace_addr=0x" + Long.toHexString(userspace_addr) + ", vaddr_off=0x" + Long.toHexString(vaddr_off));
    }

    private UserMemoryRegionTest kvm;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        kvm = this;
        pageSize = 0x1000;
        memoryRegionMap = new TreeMap<>();
        slotIndex = 0;
        slots = new UserMemoryRegion[0x200];

        mem_map(0x1000, 0x1000);
        mem_map(0x2000, 0x2000);
        mem_map(0x4000, 0x3000);
        mem_map(0x7000, 0x4000);

        assertEquals(4, memoryRegionMap.size());
        assertEquals(4, slotIndex);
    }

    public void testMMap06() {
        mem_unmap(0x3000, 0x6000);
        assertEquals(3, memoryRegionMap.size());
        List<UserMemoryRegion> list = new ArrayList<>(memoryRegionMap.values());

        UserMemoryRegion region = list.get(1);
        assertEquals(0x2000, region.guest_phys_addr);
        assertEquals(0x2000, region.userspace_addr);
        assertEquals(0x1000, region.memory_size);

        region = list.get(2);
        assertEquals(0x9000, region.guest_phys_addr);
        assertEquals(0x9000, region.userspace_addr);
        assertEquals(0x2000, region.memory_size);
    }

    public void testMMap05() {
        mem_unmap(0x2000, 0x6000);
        assertEquals(2, memoryRegionMap.size());
        List<UserMemoryRegion> list = new ArrayList<>(memoryRegionMap.values());

        UserMemoryRegion region = list.get(1);
        assertEquals(0x8000, region.guest_phys_addr);
        assertEquals(0x8000, region.userspace_addr);
        assertEquals(0x3000, region.memory_size);
    }

    public void testMMap04() {
        mem_unmap(0x8000, 0x2000);
        assertEquals(5, memoryRegionMap.size());
        List<UserMemoryRegion> list = new ArrayList<>(memoryRegionMap.values());

        UserMemoryRegion region = list.get(3);
        assertEquals(0x7000, region.guest_phys_addr);
        assertEquals(0x7000, region.userspace_addr);
        assertEquals(0x1000, region.memory_size);

        region = list.get(4);
        assertEquals(0xa000, region.guest_phys_addr);
        assertEquals(0xa000, region.userspace_addr);
        assertEquals(0x1000, region.memory_size);
    }

    public void testMMap03() {
        mem_unmap(0x5000, 0x2000);
        assertEquals(4, memoryRegionMap.size());
        List<UserMemoryRegion> list = new ArrayList<>(memoryRegionMap.values());
        UserMemoryRegion region = list.get(2);
        assertEquals(0x4000, region.guest_phys_addr);
        assertEquals(0x4000, region.userspace_addr);
        assertEquals(0x1000, region.memory_size);
    }

    public void testMMap02() {
        mem_unmap(0x4000, 0x1000);
        assertEquals(4, memoryRegionMap.size());
        List<UserMemoryRegion> list = new ArrayList<>(memoryRegionMap.values());
        UserMemoryRegion region = list.get(2);
        assertEquals(0x5000, region.guest_phys_addr);
        assertEquals(0x5000, region.userspace_addr);
        assertEquals(0x2000, region.memory_size);
    }

    public void testMMap01() {
        mem_unmap(0x1000, 0x1000);
        assertEquals(3, memoryRegionMap.size());
        List<UserMemoryRegion> list = new ArrayList<>(memoryRegionMap.values());
        UserMemoryRegion region = list.get(0);
        assertEquals(0x2000, region.guest_phys_addr);
        assertEquals(0, slotIndex);
        assertNull(slots[0]);

        mem_map(0x1000, 0x1000);
        assertEquals(1, slotIndex);
    }

    private void mem_map(long address, long size) {
        if ((address & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_map address=0x" + Long.toHexString(address));
        }
        if ((size & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_map size=0x" + Long.toHexString(size));
        }

        int slot = allocateSlot();
        long userspace_addr = kvm.set_user_memory_region(slot, address, size, 0L);
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

    private void mem_unmap(long address, long size) throws BackendException {
        if ((address & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_unmap address=0x" + Long.toHexString(address));
        }
        if ((size & (pageSize - 1)) != 0) {
            throw new IllegalArgumentException("mem_unmap size=0x" + Long.toHexString(size));
        }

        for (long i = address; i < address + size; i += pageSize) {
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

            mem_unmap_page(i, userMemoryRegion);
        }
    }

}
