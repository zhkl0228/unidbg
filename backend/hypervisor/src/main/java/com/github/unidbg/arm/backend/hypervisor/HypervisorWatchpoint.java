package com.github.unidbg.arm.backend.hypervisor;

import capstone.Arm64_const;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class HypervisorWatchpoint implements BreakRestorer {

    private static final Logger log = LoggerFactory.getLogger(HypervisorWatchpoint.class);

    /** DBGWCR: E=1 (enabled), PAC=0b10 (EL1 & EL0) */
    private static final long DBGWCR_ENABLE = 0x5L;
    /** DBGWCR LSC field: store only */
    private static final long DBGWCR_LSC_STORE = 0b10L << 3;
    /** DBGWCR LSC field: load only */
    private static final long DBGWCR_LSC_LOAD = 0b01L << 3;
    /** DBGWCR BAS field bit offset */
    private static final int DBGWCR_BAS_SHIFT = 5;
    /** DBGWCR MASK field bit offset */
    private static final int DBGWCR_MASK_SHIFT = 24;
    /** Full byte-address-select mask (all 8 bytes selected) */
    private static final long DBGWCR_BAS_FULL = 0xFFL;

    private final ReadHook readHook;
    private final WriteHook writeHook;
    private final long begin;
    private final long end;
    private final Object userData;
    private final int slot;
    private final boolean isWrite;

    private final long dbgwcr, dbgwvr, bytes;

    HypervisorWatchpoint(Object callback, long begin, long end, Object userData, int slot, boolean isWrite) {
        if (begin >= end) {
            throw new IllegalArgumentException("Watchpoint begin must be less than end: begin=0x" + Long.toHexString(begin) + ", end=0x" + Long.toHexString(end));
        }

        long size = end - begin;
        if ((size >>> 31) != 0) {
            throw new IllegalArgumentException("too large size=0x" + Long.toHexString(size));
        }

        if (isWrite) {
            this.writeHook = (WriteHook) callback;
            this.readHook = null;
        } else {
            this.readHook = (ReadHook) callback;
            this.writeHook = null;
        }
        this.begin = begin;
        this.end = end;
        this.userData = userData;
        this.slot = slot;
        this.isWrite = isWrite;

        long[] config = computeWatchpointConfig(begin, size, isWrite);
        if (config == null) {
            throw new UnsupportedOperationException("Failed to find a power-of-2 aligned region for watchpoint: begin=0x" + Long.toHexString(begin) + ", end=0x" + Long.toHexString(end));
        }
        this.dbgwcr = config[0];
        this.dbgwvr = config[1];
        this.bytes = config[2];
    }

    /**
     * Finds the smallest power-of-2 aligned region that covers [begin, begin+size),
     * and computes the DBGWCR/DBGWVR register values for the ARM watchpoint hardware.
     *
     * @return {dbgwcr, dbgwvr, bytes} or null if no suitable region found
     */
    private static long[] computeWatchpointConfig(long begin, long size, boolean isWrite) {
        long dbgwcr = DBGWCR_ENABLE | (isWrite ? DBGWCR_LSC_STORE : DBGWCR_LSC_LOAD);
        for (int i = 2; i <= 31; i++) {
            int bytes = 1 << i;
            int mask = bytes - 1;
            long dbgwvr = begin & ~mask;
            long offset = begin - dbgwvr;
            if (offset + size <= bytes) {
                long bas;
                int maskBits;
                if (i <= 3) {
                    maskBits = 0;
                    bas = 0;
                    for (long m = 0; m < size; m++) {
                        bas |= (1L << (offset + m));
                    }
                } else {
                    maskBits = i;
                    bas = DBGWCR_BAS_FULL;
                }
                dbgwcr |= (bas << DBGWCR_BAS_SHIFT);
                dbgwcr |= ((long) maskBits << DBGWCR_MASK_SHIFT);

                if (log.isDebugEnabled()) {
                    log.debug("begin=0x{}, end=0x{}, dbgwvr=0x{}, dbgwcr=0x{}, offset={}, size={}, i={}", Long.toHexString(begin), Long.toHexString(begin + size), Long.toHexString(dbgwvr), Long.toHexString(dbgwcr), offset, size, i);
                }
                return new long[]{dbgwcr, dbgwvr, bytes};
            }
        }
        return null;
    }

    int getSlot() {
        return slot;
    }

    final boolean matches(long begin, long end, boolean isWrite) {
        return this.begin == begin && this.end == end && this.isWrite == isWrite;
    }

    /**
     * Coarse check using the hardware-aligned region (dbgwvr/bytes) to quickly
     * determine if an access overlaps the watchpoint's monitored range.
     */
    final boolean contains(long address, int accessSize, boolean isWrite) {
        if (isWrite ^ this.isWrite) {
            return false;
        }
        if (accessSize <= 0) {
            accessSize = 1;
        }
        long accessEnd = address + accessSize;
        return address < (dbgwvr + bytes) && accessEnd > dbgwvr;
    }

    /**
     * Fine-grained callback dispatch using the exact user-specified range (begin/end),
     * invoked only after {@link #contains} passes the coarse hardware-level check.
     */
    final void onHit(Backend backend, long address, int accessSize, boolean isWrite, Instruction insn) {
        long accessEnd = address + accessSize;
        if (address >= end || accessEnd <= begin) {
            return;
        }
        switch (insn.getMnemonic()) {
            case "ldp":
            case "ldxp":
            case "ldaxp":
            case "stp":
            case "stxp":
            case "stlxp": {
                int halfSize = accessSize / 2;
                int baseRegIndex = pairFirstRegIndex(insn.getMnemonic());
                notifySubAccess(backend, address, halfSize, isWrite, insn, baseRegIndex);
                notifySubAccess(backend, address + halfSize, halfSize, isWrite, insn, baseRegIndex + 1);
                return;
            }
        }
        notifySubAccess(backend, address, accessSize, isWrite, insn, singleRegIndex(insn.getMnemonic()));
    }

    private void notifySubAccess(Backend backend, long address, int size, boolean isWrite, Instruction insn, int regIndex) {
        if (address >= end || (address + size) <= begin) {
            return;
        }
        if (isWrite) {
            long value = extractWriteValue(insn, backend, size, regIndex);
            writeHook.hook(backend, address, size, value, userData);
        } else {
            readHook.hook(backend, address, size, userData);
        }
    }

    private static int pairFirstRegIndex(String mnemonic) {
        switch (mnemonic) {
            case "stxp":
            case "stlxp":
                return 1;
            default:
                return 0;
        }
    }

    private static int singleRegIndex(String mnemonic) {
        switch (mnemonic) {
            case "stxr":
            case "stlxr":
                return 1;
            default:
                return 0;
        }
    }

    private static long extractWriteValue(Instruction insn, Backend backend, int size, int regIndex) {
        OpInfo opInfo = (OpInfo) insn.getOperands();
        Operand[] ops = opInfo.getOperands();
        if (ops.length > regIndex && ops[regIndex].getType() == Arm64_const.ARM64_OP_REG) {
            int unicornReg = insn.mapToUnicornReg(ops[regIndex].getValue().getReg());
            long value = backend.reg_read(unicornReg).longValue();
            switch (size) {
                case 1: return value & 0xFFL;
                case 2: return value & 0xFFFFL;
                case 4: return value & 0xFFFFFFFFL;
                default: return value;
            }
        }
        return 0;
    }

    @Override
    public final void install(Hypervisor hypervisor) {
        hypervisor.install_watchpoint(slot, dbgwcr, dbgwvr);
    }
}
