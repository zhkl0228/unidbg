package com.github.unidbg.arm.backend.hypervisor;

import capstone.Arm64_const;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.arm.backend.hypervisor.arm64.MemorySizeDetector;
import com.github.unidbg.arm.backend.hypervisor.arm64.SimpleMemorySizeDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class HypervisorWatchpoint implements BreakRestorer {

    private static final Logger log = LoggerFactory.getLogger(HypervisorWatchpoint.class);
    private static final MemorySizeDetector MEMORY_SIZE_DETECTOR = new SimpleMemorySizeDetector();

    private final Object callback;
    private final long begin;
    private final long end;
    private final Object user_data;
    final int n;
    private final boolean isWrite;

    private final long dbgwcr, dbgwvr, bytes;

    HypervisorWatchpoint(Object callback, long begin, long end, Object user_data, int n, boolean isWrite) {
        if (begin >= end) {
            throw new IllegalArgumentException("begin=0x" + Long.toHexString(begin) + ", end=" + Long.toHexString(end));
        }

        long size = end - begin;
        if ((size >>> 31) != 0) {
            throw new IllegalArgumentException("too large size=0x" + Long.toHexString(size));
        }

        this.callback = callback;
        this.begin = begin;
        this.end = end;
        this.user_data = user_data;
        this.n = n;
        this.isWrite = isWrite;

        long dbgwcr = 0x5;
        if (isWrite) {
            dbgwcr |= 0b10 << 3;
        } else {
            dbgwcr |= 0b01 << 3;
        }
        for (int i = 2; i <= 31; i++) {
            int bytes = 1 << i;
            int mask = bytes - 1;
            long dbgwvr = begin & ~mask;
            long offset = begin - dbgwvr;
            if(offset + size <= bytes) {
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
                    bas = 0xff;
                }
                dbgwcr |= (bas << 5);
                dbgwcr |= (maskBits << 24);

                if (log.isDebugEnabled()) {
                    log.debug("begin=0x{}, end=0x{}, dbgwvr=0x{}, dbgwcr=0x{}, offset={}, size={}, i={}", Long.toHexString(begin), Long.toHexString(end), Long.toHexString(dbgwvr), Long.toHexString(dbgwcr), offset, size, i);
                }

                this.bytes = bytes;
                this.dbgwvr = dbgwvr;
                this.dbgwcr = dbgwcr;
                return;
            }
        }

        throw new UnsupportedOperationException("begin=0x" + Long.toHexString(begin) + ", end=0x" + Long.toHexString(end));
    }

    final boolean matches(long begin, long end, boolean isWrite) {
        return this.begin == begin && this.end == end && this.isWrite == isWrite;
    }

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

    static int detectAccessSize(Instruction insn, boolean isWrite) {
        if (isWrite) {
            return MEMORY_SIZE_DETECTOR.detectWriteSize(insn);
        } else {
            return MEMORY_SIZE_DETECTOR.detectReadSize(insn);
        }
    }

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
            ((WriteHook) callback).hook(backend, address, size, value, user_data);
        } else {
            ((ReadHook) callback).hook(backend, address, size, user_data);
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
        hypervisor.install_watchpoint(n, dbgwcr, dbgwvr);
    }
}
