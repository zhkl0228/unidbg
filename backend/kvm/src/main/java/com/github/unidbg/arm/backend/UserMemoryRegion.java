package com.github.unidbg.arm.backend;

final class UserMemoryRegion {

    final int slot;
//    int flags;
    final long guest_phys_addr;
    final long memory_size; /* bytes */
    final long userspace_addr; /* start of the userspace allocated memory */

    UserMemoryRegion(int slot, long guest_phys_addr, long memory_size, long userspace_addr) {
        this.slot = slot;
        this.guest_phys_addr = guest_phys_addr;
        this.memory_size = memory_size;
        this.userspace_addr = userspace_addr;
    }

    @Override
    public String toString() {
        return "UserMemoryRegion{" +
                "slot=" + slot +
                ", guest_phys_addr=0x" + Long.toHexString(guest_phys_addr) +
                ", memory_size=0x" + Long.toHexString(memory_size) +
                ", userspace_addr=0x" + Long.toHexString(userspace_addr) +
                '}';
    }

}
