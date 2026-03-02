package com.github.unidbg.arm.backend.hypervisor;

import capstone.api.Disassembler;
import capstone.api.DisassemblerFactory;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.OpValue;
import capstone.api.arm64.Operand;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.Family;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.arm.backend.hypervisor.arm64.MemorySizeDetector;
import com.github.unidbg.arm.backend.hypervisor.arm64.SimpleMemorySizeDetector;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

import java.util.*;

public class HypervisorBackend64 extends HypervisorBackend {

    private static final Logger log = LoggerFactory.getLogger(HypervisorBackend64.class);

    private static final MemorySizeDetector MEMORY_SIZE_DETECTOR = new SimpleMemorySizeDetector();

    public HypervisorBackend64(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);

        breakpoints = new HypervisorBreakPoint[hypervisor.getBRPs()];
        watchpoints = new HypervisorWatchpoint[hypervisor.getWRPs()];
    }

    private Disassembler disassembler;
    private Keystone keystone;

    private synchronized Disassembler createDisassembler() {
        if (disassembler == null) {
            this.disassembler = DisassemblerFactory.createArm64Disassembler();
            this.disassembler.setDetail(true);
        }
        return disassembler;
    }

    private synchronized Keystone getKeystone() {
        if (keystone == null) {
            this.keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
        }
        return keystone;
    }

    private static final long DARWIN_KERNEL_BASE = 0xffffff80001f0000L;
    private static final long _COMM_PAGE64_BASE_ADDRESS = DARWIN_KERNEL_BASE + 0xc000 /* In TTBR0 */;

    @Override
    public void mem_map(long address, long size, int perms) throws BackendException {
        if (address == DARWIN_KERNEL_BASE) {
            throw new BackendException();
        }

        super.mem_map(address, size, perms);
    }

    private DebugHook debugCallback;
    private Object debugUserData;
    private long debugBegin;
    private long debugEnd;

    @Override
    public void debugger_add(DebugHook callback, long begin, long end, Object userData) throws BackendException {
        this.debugCallback = callback;
        this.debugUserData = userData;
        this.debugBegin = begin;
        this.debugEnd = end;
    }

    private final HypervisorBreakPoint[] breakpoints;
    private final Deque<ExceptionVisitor> visitorStack = new ArrayDeque<>();

    private int singleStep;

    @Override
    public void setSingleStep(int singleStep) {
        this.singleStep = singleStep;
        step();
    }

    @Override
    public BreakPoint addBreakPoint(long address, BreakPointCallback callback, boolean thumb) {
        if (thumb) {
            throw new IllegalStateException();
        }
        int freeSlot = -1;
        for (int i = 0; i < breakpoints.length; i++) {
            if (breakpoints[i] != null && breakpoints[i].getAddress() == address) {
                return breakpoints[i];
            }
            if (freeSlot == -1 && breakpoints[i] == null) {
                freeSlot = i;
            }
        }
        if (freeSlot != -1) {
            HypervisorBreakPoint bp = new HypervisorBreakPoint(freeSlot, address, callback);
            bp.install(hypervisor);
            breakpoints[freeSlot] = bp;
            return bp;
        }
        throw new UnsupportedOperationException("Max BKPs: " + breakpoints.length);
    }

    @Override
    public boolean removeBreakPoint(long address) {
        for (int i = 0; i < breakpoints.length; i++) {
            if (breakpoints[i] != null && breakpoints[i].getAddress() == address) {
                breakpoints[i] = null;
                hypervisor.disable_hw_breakpoint(i);
                return true;
            }
        }
        return false;
    }

    @Override
    public void handleUnknownException(int ec, long esr, long far, long virtualAddress) {
        switch (ec) {
            case EC_DATAABORT:
                boolean isv = (esr & ARM_EL_ISV) != 0;
                boolean isWrite = ((esr >> 6) & 1) != 0;
                int sas = (int) ((esr >> 22) & 3);
                int accessSize = isv ? 1 << sas : 0;
                if (log.isDebugEnabled()) {
                    log.debug("handleDataAbort isWrite={}, accessSize={}, virtualAddress=0x{}", isWrite, accessSize, Long.toHexString(virtualAddress));
                }
                if (eventMemHookNotifier != null) {
                    eventMemHookNotifier.notifyDataAbort(isWrite, accessSize, virtualAddress);
                }
                break;
            case EC_INSNABORT:
                if (eventMemHookNotifier != null) {
                    eventMemHookNotifier.notifyInsnAbort(virtualAddress);
                }
                break;
            default:
                log.warn("handleUnknownException ec=0x{}, virtualAddress=0x{}, esr=0x{}, far=0x{}", Integer.toHexString(ec), Long.toHexString(virtualAddress), Long.toHexString(esr), Long.toHexString(far));
                break;
        }
    }

    private long lastHitPointAddress = -1;

    @Override
    public boolean handleException(long esr, long far, final long elr, long cpsr) {
        int ec = (int) ((esr >> 26) & 0x3f);
        if (log.isDebugEnabled()) {
            log.debug("handleException syndrome=0x{}, far=0x{}, elr=0x{}, ec=0x{}, cpsr=0x{}", Long.toHexString(esr), Long.toHexString(far), Long.toHexString(elr), Integer.toHexString(ec), Long.toHexString(cpsr));
        }
        if (lastHitPointAddress != elr &&
                (ec == EC_SOFTWARESTEP || ec == EC_BREAKPOINT || ec == EC_WATCHPOINT)) {
            while (!visitorStack.isEmpty()) {
                if (visitorStack.pop().onException(hypervisor, ec, elr)) {
                    return true;
                }
            }
            lastHitPointAddress = -1;
        }
        switch (ec) {
            case EC_AA64_SVC: {
                int swi = (int) (esr & 0xffff);
                callSVC(elr, swi);
                return true;
            }
            case EC_AA64_BKPT: {
                int bkpt = (int) (esr & 0xffff);
                notifyInterruptHook(ARMEmulator.EXCP_BKPT, bkpt);
                return true;
            }
            case EC_SOFTWARESTEP:
                onSoftwareStep(esr, elr, cpsr);
                return true;
            case EC_BREAKPOINT:
                lastHitPointAddress = elr;
                handleBreakpoint(esr, elr);
                return true;
            case EC_WATCHPOINT:
                lastHitPointAddress = elr;
                onWatchpoint(esr, far, elr);
                return true;
            case EC_DATAABORT:
                return handleDataAbort(ec, esr, far, elr);
            case EC_SYSTEMREGISTERTRAP:
                return handleSystemRegisterTrap(esr, elr);
            default:
                log.warn("handleException ec=0x{}", Integer.toHexString(ec));
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec));
        }
    }

    private void handleBreakpoint(long esr, long elr) {
        notifyDebugEvent(esr, elr);
        for (int i = 0; i < breakpoints.length; i++) {
            HypervisorBreakPoint bp = breakpoints[i];
            if (bp != null && bp.getAddress() == elr) {
                hypervisor.disable_hw_breakpoint(i);
                visitorStack.push(ExceptionVisitor.breakRestorerVisitor(bp));
                step();
                break;
            }
        }
    }

    private boolean handleDataAbort(int ec, long esr, long far, long elr) {
        boolean isv = (esr & ARM_EL_ISV) != 0;
        int sas = (int) ((esr >> 22) & 3);
        int dfsc = (int) (esr & 0x3f);
        if (log.isDebugEnabled()) {
            boolean isWrite = ((esr >> 6) & 1) != 0;
            boolean s1ptw = ((esr >> 7) & 1) != 0;
            int len = 1 << sas;
            int srt = (int) ((esr >> 16) & 0x1f);
            log.debug("handle EC_DATAABORT isv={}, isWrite={}, s1ptw={}, len={}, srt={}, dfsc=0x{}, vaddr=0x{}", isv, isWrite, s1ptw, len, srt, Integer.toHexString(dfsc), Long.toHexString(far));
        }
        if (dfsc == 0x00 && emulator.getFamily() == Family.iOS) {
            int accessSize = isv ? 1 << sas : 0;
            return handleCommRead(far, elr, accessSize);
        }
        throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec) + ", dfsc=0x" + Integer.toHexString(dfsc));
    }

    private boolean handleSystemRegisterTrap(long esr, long elr) {
        /*
         *  Direction: Indicates the direction of the trapped instruction.
         *  0b0	Write access, including MSR instructions.
         *  0b1	Read access, including MRS instructions.
         */
        boolean isRead = (esr & 1) != 0;
        int CRm = (int) ((esr >>> 1) & 0xf);
        int Rt = (int) ((esr >>> 5) & 0x1f);
        int CRn = (int) ((esr >>> 10) & 0xf);
        int Op1 = ((int) (esr >>> 14) & 0x7);
        int Op2 = ((int) (esr >>> 17) & 0x7);
        int Op0 = ((int) (esr >>> 20) & 0x3);
        if (isRead) {
            if (CRm == 0 && CRn == 14 && Op1 == 3 && Op0 == 3
                    && (Op2 == 1 /* CNTPCT_EL0 */ || Op2 == 2 /* CNTVCT_EL0 */)) {
                if (Rt < 31) {
                    hypervisor.reg_write64(Rt, 0);
                }
                hypervisor.reg_set_elr_el1(elr + 4);
                return true;
            }
        }
        throw new UnsupportedOperationException("EC_SYSTEMREGISTERTRAP isRead=" + isRead + ", CRm=" + CRm + ", CRn=" + CRn + ", Op1=" + Op1 + ", Op2=" + Op2 + ", Op0=" + Op0);
    }

    private void step() {
        if (singleStep < 0) {
            singleStep = 0;
        }
        hypervisor.enable_single_step(true);
    }

    private final HypervisorWatchpoint[] watchpoints;

    private void installWatchpoint(Object callback, long begin, long end, Object userData, boolean isWrite) {
        int freeSlot = -1;
        for (int i = 0; i < watchpoints.length; i++) {
            if (watchpoints[i] != null && watchpoints[i].matches(begin, end, isWrite)) {
                return;
            }
            if (freeSlot == -1 && watchpoints[i] == null) {
                freeSlot = i;
            }
        }
        if (freeSlot != -1) {
            HypervisorWatchpoint wp = new HypervisorWatchpoint(callback, begin, end, userData, freeSlot, isWrite);
            wp.install(hypervisor);
            watchpoints[freeSlot] = wp;
            return;
        }
        throw new UnsupportedOperationException("Max WRPs: " + watchpoints.length);
    }

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object userData) throws BackendException {
        installWatchpoint(callback, begin, end, userData, false);
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object userData) throws BackendException {
        installWatchpoint(callback, begin, end, userData, true);
    }

    private long lastWatchpointAddress = -1;
    private long lastWatchpointDataAddress = -1;

    private static boolean isLoadExclusiveCode(int asm) {
        if ((asm & 0xbffffc00) == 0x885ffc00) { // ldaxr
            return true;
        }
        if ((asm & 0xbffffc00) == 0x885f7c00) { // ldxr
            return true;
        }
        if ((asm & 0xbfff8000) == 0x887f8000) { // ldaxp
            return true;
        }
        if ((asm & 0xbfff8000) == 0x887f0000) { // ldxp
            return true;
        }
        if ((asm & 0xfffffc00) == 0x485ffc00) { // ldaxrh
            return true;
        }
        if ((asm & 0xfffffc00) == 0x485f7c00) { // ldxrh
            return true;
        }
        if ((asm & 0xfffffc00) == 0x085ffc00) { // ldaxrb
            return true;
        }
        return (asm & 0xfffffc00) == 0x085f7c00; // ldxrb
    }

    private void onWatchpoint(long esr, long address, long elr) {
        Pointer pc = Objects.requireNonNull(UnidbgPointer.pointer(emulator, elr));
        byte[] code = pc.getByteArray(0, 4);
        boolean repeatWatchpoint = lastWatchpointAddress == elr
                && lastWatchpointDataAddress == address
                && isLoadExclusiveCode(pc.getInt(0));
        if (!repeatWatchpoint) {
            lastWatchpointAddress = elr;
            lastWatchpointDataAddress = address;
        }
        boolean write = ((esr >> 6) & 1) == 1;
        int status = (int) (esr & 0x3f);
        if (log.isDebugEnabled()) {
            boolean cm = ((esr >> 8) & 1) == 1;
            int wpt = (int) ((esr >> 18) & 0x3f);
            boolean wptv = ((esr >> 17) & 1) == 1;
            log.debug("onWatchpoint write={}, address=0x{}, cm={}, wpt={}, wptv={}, status=0x{}", write, Long.toHexString(address), cm, wpt, wptv, Integer.toHexString(status));
        }
        Instruction insn = createDisassembler().disasm(code, elr, 1)[0];
        int accessSize = write ? MEMORY_SIZE_DETECTOR.detectWriteSize(insn) : MEMORY_SIZE_DETECTOR.detectReadSize(insn);
        HypervisorWatchpoint hitWp = null;
        for (HypervisorWatchpoint watchpoint : watchpoints) {
            if (watchpoint != null && watchpoint.contains(address, accessSize, write)) {
                hitWp = watchpoint;
                break;
            }
        }
        if (hitWp == null) {
            notifyInterruptHook(ARMEmulator.EXCP_BKPT, status);
        } else if (repeatWatchpoint) {
            if (exclusiveMonitorEscaper != null) {
                notifyInterruptHook(ARMEmulator.EXCP_BKPT, status);
            } else {
                exclusiveMonitorEscaper = new WatchpointEscaper(hitWp);
                step();
            }
        } else {
            hitWp.onHit(this, address, accessSize, write, insn);
            hypervisor.disable_watchpoint(hitWp.getSlot());
            visitorStack.push(ExceptionVisitor.breakRestorerVisitor(hitWp));
            step();
        }
    }

    private boolean isInDebugRange(long address) {
        return debugBegin >= debugEnd || (address >= debugBegin && address < debugEnd);
    }

    private void notifyDebugEvent(long esr, long address) {
        if (debugCallback != null && isInDebugRange(address)) {
            debugCallback.onBreak(this, address, INS_SIZE, debugUserData);
        } else {
            int status = (int) (esr & 0x3f);
            notifyInterruptHook(ARMEmulator.EXCP_BKPT, status);
        }
    }

    /**
     * The local exclusive monitor gets cleared on every exception return, that is, on execution of the ERET instruction.
     * <p>
     * from: <a href="https://xen-devel.narkive.com/wQw4F6GV/xen-arm-software-step-armv8-pc-stuck-on-instruction">xen-arm-software-step-armv8-pc-stuck-on-instruction</a>
     * LDAXR sets the 'exclusive monitor' and STXR only succeeds if the exclusive
     * monitor is still set. If another CPU accesses the memory protected by the
     * exclusive monitor, the monitor is cleared. This is how the spinlock code knows
     * it has to re-read its value and try to take the lock again.
     * Changing exception level also clears the exclusive monitor, so taking
     * single-step exception between a LDAXR/STXR pair means the loop has to be retried.
     */
    private abstract class ExclusiveMonitorEscaper {
        private long loadExclusiveAddress = -1;
        private int loadExclusiveCount;
        private final Set<Long> exclusiveRegionAddressList = new LinkedHashSet<>();
        private void resetRegionInfo() {
            loadExclusiveAddress = -1;
            loadExclusiveCount = 0;
            exclusiveRegionAddressList.clear();
        }
        final void onSoftwareStep(long spsr, long address) {
            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
            if (pointer == null) {
                hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
                return;
            }
            updateExclusiveDetection(pointer.getInt(0), address);
            if (loadExclusiveCount >= 4 && address == loadExclusiveAddress) {
                if (tryEscapeExclusiveLoop(spsr, address)) {
                    return;
                }
            }
            if (shouldAbandonEscape()) {
                onEscapeSuccess();
                return;
            }
            if (notifyCallback(address)) {
                hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
            }
        }
        private void updateExclusiveDetection(int asm, long address) {
            if (isLoadExclusiveCode(asm)) {
                if (loadExclusiveAddress == address) {
                    loadExclusiveCount++;
                } else {
                    loadExclusiveCount = 0;
                }
                loadExclusiveAddress = address;
            } else {
                if (loadExclusiveAddress == -1) {
                    resetRegionInfo();
                }
            }
            if (loadExclusiveCount >= 2) {
                exclusiveRegionAddressList.add(address);
            }
        }
        private boolean tryEscapeExclusiveLoop(long spsr, long address) {
            long foundAddress = 0;
            for (long pc : exclusiveRegionAddressList) {
                Pointer ptr = Objects.requireNonNull(UnidbgPointer.pointer(emulator, pc));
                byte[] code = ptr.getByteArray(0, 4);
                Instruction instruction = createDisassembler().disasm(code, pc, 1)[0];
                switch (instruction.getMnemonic()) {
                    case "stxr":
                    case "stlxr":
                    case "stxp":
                    case "stlxp":
                    case "stxrh":
                    case "stlxrh":
                    case "stxrb":
                    case "stlxrb":
                        foundAddress = pc;
                        break;
                }
            }
            if (foundAddress == 0) {
                if (log.isWarnEnabled()) {
                    StringBuilder builder = new StringBuilder();
                    for (long pc : exclusiveRegionAddressList) {
                        Pointer ptr = Objects.requireNonNull(UnidbgPointer.pointer(emulator, pc));
                        byte[] code = ptr.getByteArray(0, 4);
                        Instruction instruction = createDisassembler().disasm(code, pc, 1)[0];
                        builder.append(String.format("0x%x: %s%n", instruction.getAddress(), instruction));
                    }
                    log.warn("No store-exclusive found in exclusive region, skipping escape: \n{}", builder);
                }
                resetRegionInfo();
                return false;
            }
            resetRegionInfo();
            final long breakAddress = foundAddress + 4;
            for (int i = 0; i < breakpoints.length; i++) {
                if (breakpoints[i] == null) {
                    final int n = i;
                    visitorStack.push(new ExceptionVisitor() {
                        @Override
                        public boolean onException(Hypervisor hypervisor, int ec, long address) {
                            if (ec == EC_BREAKPOINT) {
                                notifyCallback(address);
                            }
                            breakpoints[n] = null;
                            hypervisor.disable_hw_breakpoint(n);
                            onEscapeSuccess();
                            return true;
                        }
                    });
                    notifyCallback(address);
                    HypervisorBreakPoint bp = new HypervisorBreakPoint(n, breakAddress, null);
                    bp.install(hypervisor);
                    breakpoints[n] = bp;
                    hypervisor.enable_single_step(false);
                    hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
                    return true;
                }
            }
            log.warn("No free breakpoint slot for exclusive monitor escape, max BKPs: {}", breakpoints.length);
            resetRegionInfo();
            return false;
        }
        /**
         * @return true to continue single-stepping, false to fast-forward (skip PSTATE.SS)
         */
        abstract boolean notifyCallback(long address);
        abstract void onEscapeSuccess();
        boolean shouldAbandonEscape() { return false; }
    }

    private class CodeHookEscaper extends ExclusiveMonitorEscaper implements UnHook {
        private final CodeHook callback;
        private final long begin;
        private final long end;
        private final Object user;
        private int reentrySlot = -1;
        CodeHookEscaper(CodeHook callback, long begin, long end, Object user) {
            this.callback = callback;
            this.begin = begin;
            this.end = end;
            this.user = user;
        }
        private boolean isInRange(long address) {
            return begin >= end || (address >= begin && address < end);
        }
        @Override
        void onEscapeSuccess() {
            step();
        }
        @Override
        boolean notifyCallback(long address) {
            if (isInRange(address)) {
                callback.hook(HypervisorBackend64.this, address, 4, user);
                return true;
            }
            return !tryFastForward();
        }
        private boolean tryFastForward() {
            if (begin >= end) {
                return false;
            }
            long lr = reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
            long target = (lr >= begin && lr < end) ? lr : begin;
            for (int i = 0; i < breakpoints.length; i++) {
                if (breakpoints[i] == null) {
                    final int n = i;
                    reentrySlot = n;
                    visitorStack.push(new ExceptionVisitor() {
                        @Override
                        public boolean onException(Hypervisor hypervisor, int ec, long address) {
                            breakpoints[n] = null;
                            hypervisor.disable_hw_breakpoint(n);
                            reentrySlot = -1;
                            step();
                            return ec == EC_BREAKPOINT;
                        }
                    });
                    HypervisorBreakPoint bp = new HypervisorBreakPoint(n, target, null);
                    bp.install(hypervisor);
                    breakpoints[n] = bp;
                    hypervisor.enable_single_step(false);
                    return true;
                }
            }
            return false;
        }
        @Override
        public void unhook() {
            if (reentrySlot >= 0) {
                breakpoints[reentrySlot] = null;
                hypervisor.disable_hw_breakpoint(reentrySlot);
                reentrySlot = -1;
            }
            exclusiveMonitorEscaper = null;
            hypervisor.enable_single_step(false);
        }
    }

    private class WatchpointEscaper extends ExclusiveMonitorEscaper {
        private final HypervisorWatchpoint wp;
        private int stepCount;
        private static final int MAX_ESCAPE_STEPS = 200;
        WatchpointEscaper(HypervisorWatchpoint wp) {
            this.wp = wp;
            hypervisor.disable_watchpoint(wp.getSlot());
        }
        @Override
        boolean notifyCallback(long address) {
            return true;
        }
        @Override
        boolean shouldAbandonEscape() {
            return ++stepCount > MAX_ESCAPE_STEPS;
        }
        @Override
        void onEscapeSuccess() {
            hypervisor.enable_single_step(false);
            wp.install(hypervisor);
            lastWatchpointAddress = -1;
            lastWatchpointDataAddress = -1;
            exclusiveMonitorEscaper = null;
        }
    }

    private ExclusiveMonitorEscaper exclusiveMonitorEscaper;

    @Override
    public void hook_add_new(CodeHook callback, long begin, long end, Object userData) throws BackendException {
        if (exclusiveMonitorEscaper != null) {
            throw new IllegalStateException();
        }
        CodeHookEscaper escaper = new CodeHookEscaper(callback, begin, end, userData);
        this.exclusiveMonitorEscaper = escaper;
        step();
        callback.onAttach(escaper);
    }

    private void onSoftwareStep(long esr, long address, long spsr) {
        if (exclusiveMonitorEscaper != null) {
            exclusiveMonitorEscaper.onSoftwareStep(spsr, address);
            return;
        }

        if (singleStep <= 0) {
            hypervisor.enable_single_step(false);
            return;
        }
        if (--singleStep == 0) {
            hypervisor.enable_single_step(false);
            notifyDebugEvent(esr, address);
        } else {
            hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
        }
    }

    private boolean handleCommRead(long vaddr, long elr, int accessSize) {
        Pointer pc = Objects.requireNonNull(UnidbgPointer.pointer(emulator, elr));
        byte[] code = pc.getByteArray(0, 4);
        Instruction insn = createDisassembler().disasm(code, elr, 1)[0];
        if (log.isDebugEnabled()) {
            log.debug("handleCommRead vaddr=0x{}, elr=0x{}, asm={}", Long.toHexString(vaddr), Long.toHexString(elr), insn);
        }
        OpInfo opInfo = (OpInfo) insn.getOperands();
        if (opInfo.isUpdateFlags() || opInfo.isWriteBack() || !insn.getMnemonic().startsWith("ldr") || vaddr < _COMM_PAGE64_BASE_ADDRESS) {
            if (eventMemHookNotifier != null) {
                eventMemHookNotifier.notifyDataAbort(false, accessSize, vaddr);
            }
            return false;
        }
        Operand[] op = opInfo.getOperands();
        int offset = (int) (vaddr - _COMM_PAGE64_BASE_ADDRESS);
        switch (offset) {
            case 0x38: // uint64_t max memory size
            case 0x40:
            case 0x48:
            case 0x4c:
            case 0x50:
            case 0x58:
            case 0x60:
            case 0x64:
            case 0x90:
                return emulateCommPageLdr(insn, op, elr, 0);
            case 0x22: // uint8_t number of configured CPUs
            case 0x34: // uint8_t number of active CPUs (hw.activecpu)
            case 0x35: // uint8_t number of physical CPUs (hw.physicalcpu_max)
            case 0x36: // uint8_t number of logical CPUs (hw.logicalcpu_max)
                return emulateCommPageLdr(insn, op, elr, 1);
            default:
                throw new UnsupportedOperationException("vaddr=0x" + Long.toHexString(vaddr) + ", offset=0x" + Long.toHexString(offset));
        }
    }

    private boolean emulateCommPageLdr(Instruction insn, Operand[] op, long elr, Number val) {
        OpValue value = op[0].getValue();
        reg_write(insn.mapToUnicornReg(value.getReg()), val);
        hypervisor.reg_set_elr_el1(elr + 4);
        return true;
    }

    @Override
    public void enableVFP() {
        long value = reg_read(Arm64Const.UC_ARM64_REG_CPACR_EL1).longValue();
        value |= 0x300000; // set the FPEN bits
        reg_write(Arm64Const.UC_ARM64_REG_CPACR_EL1, value);
    }

    @Override
    public void switchUserMode() {
    }

    @Override
    public void reg_write(int regId, Number value) throws BackendException {
        try {
            if (regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) {
                hypervisor.reg_write64(regId - Arm64Const.UC_ARM64_REG_X0, value.longValue());
            } else if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                hypervisor.reg_write64(regId - Arm64Const.UC_ARM64_REG_W0, value.longValue() & 0xFFFFFFFFL);
            } else {
                switch (regId) {
                    case Arm64Const.UC_ARM64_REG_SP:
                        hypervisor.reg_set_sp64(value.longValue());
                        break;
                    case Arm64Const.UC_ARM64_REG_X29:
                        hypervisor.reg_write64(29, value.longValue());
                        break;
                    case Arm64Const.UC_ARM64_REG_LR:
                        hypervisor.reg_write64(30, value.longValue());
                        break;
                    case Arm64Const.UC_ARM64_REG_TPIDR_EL0:
                        hypervisor.reg_set_tpidr_el0(value.longValue());
                        break;
                    case Arm64Const.UC_ARM64_REG_TPIDRRO_EL0:
                        hypervisor.reg_set_tpidrro_el0(value.longValue());
                        break;
                    case Arm64Const.UC_ARM64_REG_NZCV:
                        hypervisor.reg_set_nzcv(value.longValue());
                        break;
                    case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                        hypervisor.reg_set_cpacr_el1(value.longValue());
                        break;
                    default:
                        throw new HypervisorException("regId=" + regId);
                }
            }
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        try {
            if (regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) {
                return hypervisor.reg_read64(regId - Arm64Const.UC_ARM64_REG_X0);
            } else if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                return (int) (hypervisor.reg_read64(regId - Arm64Const.UC_ARM64_REG_W0) & 0xffffffffL);
            } else {
                switch (regId) {
                    case Arm64Const.UC_ARM64_REG_SP:
                        return hypervisor.reg_read_sp64();
                    case Arm64Const.UC_ARM64_REG_X29:
                        return hypervisor.reg_read64(29);
                    case Arm64Const.UC_ARM64_REG_LR:
                        return hypervisor.reg_read64(30);
                    case Arm64Const.UC_ARM64_REG_PC:
                        return hypervisor.reg_read_pc64();
                    case Arm64Const.UC_ARM64_REG_NZCV:
                        return hypervisor.reg_read_nzcv();
                    case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                        return hypervisor.reg_read_cpacr_el1();
                    default:
                        throw new HypervisorException("regId=" + regId);
                }
            }
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        KeystoneEncoded encoded = getKeystone().assemble("brk #" + svcNumber);
        return encoded.getMachineCode();
    }

    @Override
    public synchronized void destroy() throws BackendException {
        super.destroy();

        IOUtils.close(disassembler);
        disassembler = null;

        if (keystone != null) {
            keystone.close();
            keystone = null;
        }
    }

    @Override
    public long context_alloc() {
        return Hypervisor.context_alloc();
    }

    @Override
    public void context_save(long context) {
        hypervisor.context_save(context);
    }

    @Override
    public void context_restore(long context) {
        hypervisor.context_restore(context);
    }

    @Override
    public void context_free(long context) {
        Hypervisor.free(context);
    }

    private static final Map<String, Integer> CPU_FEATURES;
    static {
        Map<String, Integer> map = new HashMap<>();
        map.put("floatingpoint", 1);
        map.put("arm.AdvSIMD", 1);
        map.put("arm.FEAT_AES", 1);
        map.put("arm.FEAT_PMULL", 1);
        map.put("arm.FEAT_SHA1", 1);
        map.put("arm.FEAT_SHA256", 1);
        map.put("armv8_crc32", 1);
        map.put("arm.FEAT_LSE", 1);
        map.put("arm.FEAT_FP16", 1);
        map.put("arm.AdvSIMD_HPFPCvt", 1);
        map.put("arm.FEAT_RDM", 1);
        map.put("arm.FEAT_JSCVT", 1);
        map.put("arm.FEAT_FCMA", 1);
        map.put("arm.FEAT_LRCPC", 1);
        map.put("arm.FEAT_DPB", 1);
        map.put("arm.FEAT_SHA3", 1);
        map.put("arm.FEAT_DotProd", 1);
        map.put("arm.FEAT_SHA512", 1);
        map.put("arm.FEAT_FHM", 1);
        map.put("arm.FEAT_DIT", 1);
        map.put("arm.FEAT_LSE2", 1);
        map.put("arm.FEAT_FlagM", 1);
        map.put("arm.FEAT_SSBS", 0);
        map.put("arm.FEAT_SB", 1);
        map.put("arm.FEAT_FlagM2", 1);
        map.put("arm.FEAT_FRINTTS", 1);
        map.put("arm.FEAT_I8MM", 1);
        map.put("arm.FEAT_BF16", 1);
        map.put("arm.FEAT_BTI", 1);
        CPU_FEATURES = Collections.unmodifiableMap(map);
    }

    @Override
    public Map<String, Integer> getCpuFeatures() {
        return CPU_FEATURES;
    }
}
