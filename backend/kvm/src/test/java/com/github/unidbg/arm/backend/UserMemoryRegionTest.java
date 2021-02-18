package com.github.unidbg.arm.backend;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class UserMemoryRegionTest extends TestCase {

    protected final Map<Long, UserMemoryRegion> memoryRegionMap = new TreeMap<>();
    private int slotIndex;
    private final UserMemoryRegion[] slots = new UserMemoryRegion[0x200];

    private int allocateSlot() {
        for (int i = slotIndex; i < slots.length; i++) {
            if (slots[i] == null) {
                return i;
            }
        }
        throw new BackendException("Allocate slot failed: slotIndex=" + slotIndex + ", maxSlots=" + slots.length);
    }

    private void mem_map(long address, long size) {
        int slot = allocateSlot();
        UserMemoryRegion region = new UserMemoryRegion(slot, address, size, 0);
        memoryRegionMap.put(address, region);
        slots[slot++] = region;
        slotIndex = slot;
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        mem_map(0x1000, 0x1000);
        mem_map(0x2000, 0x2000);
        mem_map(0x4000, 0x3000);
        mem_map(0x7000, 0x4000);
        mem_map(0xb000, 0x5000);
        mem_map(0x10000, 0x6000);
    }

    public void testMMap() {
        long address = 0x16000;
        long size = 0x1000;
        List<UserMemoryRegion> list = new ArrayList<>();
        for (UserMemoryRegion region : memoryRegionMap.values()) {
            long min = Math.max(address, region.guest_phys_addr);
            long max = Math.min(address + size, region.guest_phys_addr + region.memory_size);
            if (min < max) {
                list.add(region);
            }
        }
        System.out.println(list);
    }

}
