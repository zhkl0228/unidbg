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

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

public class HypervisorBackend64 extends HypervisorBackend {

    private static final Logger log = LoggerFactory.getLogger(HypervisorBackend64.class);

    private static final int INS_SIZE = 4;

    public HypervisorBackend64(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);

        breakpoints = new HypervisorBreakPoint[hypervisor.getBRPs()];
        watchpoints = new HypervisorWatchpoint[hypervisor.getWRPs()];
    }

    private Disassembler disassembler;

    private synchronized Disassembler createDisassembler() {
        if (disassembler == null) {
            this.disassembler = DisassemblerFactory.createArm64Disassembler();
            this.disassembler.setDetail(true);
        }
        return disassembler;
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

    @Override
    public void debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException {
        this.debugCallback = callback;
        this.debugUserData = user_data;
    }

    private final HypervisorBreakPoint[] breakpoints;
    private final Stack<ExceptionVisitor> visitorStack = new Stack<>();

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
        for (HypervisorBreakPoint breakpoint : breakpoints) {
            if (breakpoint != null && breakpoint.address == address) {
                return breakpoint;
            }
        }
        for (int i = 0; i < breakpoints.length; i++) {
            if (breakpoints[i] == null) {
                HypervisorBreakPoint bp = new HypervisorBreakPoint(i, address, callback);
                bp.install(hypervisor);
                breakpoints[i] = bp;
                return bp;
            }
        }
        throw new UnsupportedOperationException("Max BKPs: " + breakpoints.length);
    }

    @Override
    public boolean removeBreakPoint(long address) {
        for (int i = 0; i < breakpoints.length; i++) {
            if (breakpoints[i] != null && breakpoints[i].address == address) {
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
                boolean isv = (esr & ARM_EL_ISV) != 0; // Instruction Syndrome Valid. Indicates whether the syndrome information in ISS[23:14] is valid.
                boolean isWrite = ((esr >> 6) & 1) != 0;
                int sas = (int) ((esr >> 22) & 3); // Syndrome Access Size. Indicates the size of the access attempted by the faulting operation.
                int accessSize = isv ? 1 << sas : 0;
                int srt = (int) ((esr >> 16) & 0x1f); // Syndrome Register Transfer. The register number of the Wt/Xt/Rt operand of the faulting instruction.
                /*
                 * Width of the register accessed by the instruction is Sixty-Four.
                 * 0b0	Instruction loads/stores a 32-bit wide register.
                 * 0b1	Instruction loads/stores a 64-bit wide register.
                 */
                boolean sf = ((esr >> 15) & 1) != 0;
                if (log.isDebugEnabled()) {
                    log.debug("handleDataAbort srt={}, sf={}, accessSize={}", srt, sf, accessSize);
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

    private long lastHitPointAddress;

    @Override
    public boolean handleException(long esr, long far, final long elr, long cpsr) {
        int ec = (int) ((esr >> 26) & 0x3f);
        if (log.isDebugEnabled()) {
            log.debug("handleException syndrome=0x{}, far=0x{}, elr=0x{}, ec=0x{}, cpsr=0x{}", Long.toHexString(esr), Long.toHexString(far), Long.toHexString(elr), Integer.toHexString(ec), Long.toHexString(cpsr));
        }
        if (lastHitPointAddress != elr &&
                (ec == EC_SOFTWARESTEP || ec == EC_BREAKPOINT)) {
            while (!visitorStack.isEmpty()) {
                if (visitorStack.pop().onException(hypervisor, ec, elr)) {
                    return true;
                }
            }
        }
        switch (ec) {
            case EC_AA64_SVC: {
                int swi = (int) (esr & 0xffff);
                callSVC(elr, swi);
                return true;
            }
            case EC_AA64_BKPT: {
                int bkpt = (int) (esr & 0xffff);
                interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, bkpt);
                return true;
            }
            case EC_SOFTWARESTEP: {
                onSoftwareStep(esr, elr, cpsr);
                return true;
            }
            case EC_BREAKPOINT: {
                lastHitPointAddress = elr;
                onBreakpoint(esr, elr);
                for (int i = 0; i < breakpoints.length; i++) {
                    HypervisorBreakPoint bp = breakpoints[i];
                    if (bp != null && bp.address == elr) {
                        hypervisor.disable_hw_breakpoint(i);
                        visitorStack.push(ExceptionVisitor.breakRestorerVisitor(bp));
                        step();
                        break;
                    }
                }
                return true;
            }
            case EC_WATCHPOINT: {
                lastHitPointAddress = elr;
                onWatchpoint(esr, far, elr);
                return true;
            }
            case EC_DATAABORT: {
                boolean isv = (esr & ARM_EL_ISV) != 0; // Instruction Syndrome Valid. Indicates whether the syndrome information in ISS[23:14] is valid.
                boolean isWrite = ((esr >> 6) & 1) != 0;
                boolean s1ptw = ((esr >> 7) & 1) != 0;
                int sas = (int) ((esr >> 22) & 3);
                int len = 1 << sas;
                int srt = (int) ((esr >> 16) & 0x1f);
                int dfsc = (int) (esr & 0x3f);
                if (log.isDebugEnabled()) {
                    log.debug("handle EC_DATAABORT isv={}, isWrite={}, s1ptw={}, len={}, srt={}, dfsc=0x{}, vaddr=0x{}", isv, isWrite, s1ptw, len, srt, Integer.toHexString(dfsc), Long.toHexString(far));
                }
                if (dfsc == 0x00 && emulator.getFamily() == Family.iOS) {
                    int accessSize = isv ? 1 << sas : 0;
                    return handleCommRead(far, elr, accessSize);
                }
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec) + ", dfsc=0x" + Integer.toHexString(dfsc));
            }
            case EC_SYSTEMREGISTERTRAP: {
                /*
                 *  Direction: Indicates the direction of the trapped instruction.
                 *  0b0	Write access, including MSR instructions.
                 *  0b1	Read access, including MRS instructions.
                 */
                boolean isRead = (esr & 1) != 0;
                int CRm = (int) ((esr >>> 1) & 0xf);
                int Rt = (int) ((esr >>> 5) & 0x1f); // The Rt value from the issued instruction, the general-purpose register used for the transfer.
                int CRn = (int) ((esr >>> 10) & 0xf);
                int Op1 = ((int) (esr >>> 14) & 0x7);
                int Op2 = ((int) (esr >>> 17) & 0x7);
                int Op0 = ((int) (esr >>> 20) & 0x3);
                if (isRead) {
                    if (CRm == 0 && CRn == 14 && Op1 == 3 && Op2 == 1 && Op0 == 3) { // CNTPCT_EL0
                        hypervisor.reg_write64(Rt, 0);
                        hypervisor.reg_set_elr_el1(elr + 4);
                        return true;
                    }
                    if (CRm == 0 && CRn == 14 && Op1 == 3 && Op2 == 2 && Op0 == 3) { // CNTVCT_EL0
                        hypervisor.reg_write64(Rt, 0);
                        hypervisor.reg_set_elr_el1(elr + 4);
                        return true;
                    }
                }
                throw new UnsupportedOperationException("EC_SYSTEMREGISTERTRAP isRead=" + isRead + ", CRm=" + CRm + ", CRn=" + CRn + ", Op1=" + Op1 + ", Op2=" + Op2 + ", Op0=" + Op0);
            }
            default:
                log.warn("handleException ec=0x{}", Integer.toHexString(ec));
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec));
        }
    }

    private void step() {
        if (singleStep < 0) {
            singleStep = 0;
        }
        hypervisor.enable_single_step(true);
    }

    private final HypervisorWatchpoint[] watchpoints;

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object user_data) throws BackendException {
        for (int i = 0; i < watchpoints.length; i++) {
            if (watchpoints[i] == null) {
                HypervisorWatchpoint wp = new HypervisorWatchpoint(callback, begin, end, user_data, i, false);
                wp.install(hypervisor);
                watchpoints[i] = wp;
                return;
            }
        }
        throw new UnsupportedOperationException("Max WRPs: " + watchpoints.length);
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object user_data) throws BackendException {
        for (int i = 0; i < watchpoints.length; i++) {
            if (watchpoints[i] == null) {
                HypervisorWatchpoint wp = new HypervisorWatchpoint(callback, begin, end, user_data, i, true);
                wp.install(hypervisor);
                watchpoints[i] = wp;
                return;
            }
        }
        throw new UnsupportedOperationException("Max WRPs: " + watchpoints.length);
    }

    private long lastWatchpointAddress;
    private long lastWatchpointDataAddress;

    private void onWatchpoint(long esr, long address, long elr) {
        boolean repeatWatchpoint = lastWatchpointAddress == elr && lastWatchpointDataAddress == address;
        if (!repeatWatchpoint) {
            lastWatchpointAddress = elr;
            lastWatchpointDataAddress = address;
        }
        boolean write = ((esr >> 6) & 1) == 1;
        int status = (int) (esr & 0x3f);
        /*
         * Cache maintenance. Indicates whether the Watchpoint exception came from a cache maintenance or address translation instruction:
         * 0b0	The Watchpoint exception was not generated by the execution of one of the System instructions identified in the description of value 1.
         * 0b1	The Watchpoint exception was generated by either the execution of a cache maintenance instruction or by a synchronous Watchpoint exception on the execution of an address translation instruction. The DC ZVA, DC GVA, and DC GZVA instructions are not classified as a cache maintenance instructions, and therefore their execution cannot cause this field to be set to 1.
         */
        boolean cm = ((esr >> 8) & 1) == 1;
        int wpt = (int) ((esr >> 18) & 0x3f); // Watchpoint number, 0 to 15 inclusive.
        boolean wptv = ((esr >> 17) & 1) == 1; // The WPT field is valid, and holds the number of a watchpoint that triggered a Watchpoint exception.
        if (log.isDebugEnabled()) {
            log.debug("onWatchpoint write={}, address=0x{}, cm={}, wpt={}, wptv={}, status=0x{}", write, Long.toHexString(address), cm, wpt, wptv, Integer.toHexString(status));
        }
        HypervisorWatchpoint hitWp = null;
        for (int n = 0; n < watchpoints.length; n++) {
            HypervisorWatchpoint watchpoint = watchpoints[n];
            if (watchpoint != null && watchpoint.contains(address, write)) {
                hitWp = watchpoint;
                if (repeatWatchpoint) {
                    break;
                }
                Pointer pc = UnidbgPointer.pointer(emulator, elr);
                assert pc != null;
                byte[] code = pc.getByteArray(0, 4);
                if (watchpoint.onHit(this, address, write, createDisassembler(), code, elr)) {
                    hypervisor.disable_watchpoint(n);
                    visitorStack.push(ExceptionVisitor.breakRestorerVisitor(watchpoint));
                    step();
                    return;
                }
            }
        }
        if (hitWp == null) {
            interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, status);
        } else {
            if (repeatWatchpoint) {
                if (exclusiveMonitorEscaper != null) {
                    interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, status);
                } else {
                    exclusiveMonitorEscaper = new ExclusiveMonitorEscaper(new WatchpointExclusiveMonitorEscaper(hitWp));
                }
            } else {
                hypervisor.disable_watchpoint(hitWp.n);
                visitorStack.push(ExceptionVisitor.breakRestorerVisitor(hitWp));
                step();
            }
        }
    }

    private class WatchpointExclusiveMonitorEscaper implements ExclusiveMonitorCallback {
        private final HypervisorWatchpoint wp;
        WatchpointExclusiveMonitorEscaper(HypervisorWatchpoint wp) {
            this.wp = wp;
            hypervisor.disable_watchpoint(wp.n);
        }
        @Override
        public void notifyCallback(long address) {
        }
        @Override
        public void onEscapeSuccess() {
            wp.install(hypervisor);
            exclusiveMonitorEscaper = null;
        }
    }

    private void onBreakpoint(long esr, long elr) {
        if (debugCallback != null) {
            debugCallback.onBreak(this, elr, INS_SIZE, debugUserData);
        } else {
            int status = (int) (esr & 0x3f);
            interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, status);
        }
    }

    private interface ExclusiveMonitorCallback {
        void notifyCallback(long address);
        void onEscapeSuccess();
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
    private class ExclusiveMonitorEscaper {
        private final ExclusiveMonitorCallback callback;
        ExclusiveMonitorEscaper(ExclusiveMonitorCallback callback) {
            this.callback = callback;
            step();
        }
        private long loadExclusiveAddress;
        private int loadExclusiveCount;
        private final List<Long> exclusiveRegionAddressList = new ArrayList<>();
        private void resetRegionInfo() {
            loadExclusiveAddress = 0;
            loadExclusiveCount = 0;
            exclusiveRegionAddressList.clear();
        }
        private boolean isLoadExclusiveCode(int asm) {
            if ((asm & 0xbffffc00) == 0x885ffc00) { // ldaxr
                return true;
            }
            if ((asm & 0xfffffc00) == 0x485ffc00) { // ldaxrh
                return true;
            }
            if ((asm & 0xfffffc00) == 0x485f7c00) { // 0x40808dbc: ldxrh w5, [x1]
                return true;
            }
            return (asm & 0xbffffc00) == 0x885f7c00; // ldxr
        }
        final void onSoftwareStep(long spsr, long address) {
            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
            if (pointer == null) {
                hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
                return;
            }
            int asm = pointer.getInt(0);
            if (isLoadExclusiveCode(asm)) {
                if (loadExclusiveAddress == address) {
                    loadExclusiveCount++;
                } else {
                    loadExclusiveCount = 0;
                }
                loadExclusiveAddress = address;
            } else {
                if (loadExclusiveAddress == 0) {
                    resetRegionInfo();
                }
            }
            if (loadExclusiveCount >= 2 && !exclusiveRegionAddressList.contains(address)) {
                exclusiveRegionAddressList.add(address);
            }
            if (loadExclusiveCount >= 4 && address == loadExclusiveAddress) {
                long foundAddress = 0;
                StringBuilder builder = new StringBuilder();
                for (long pc : exclusiveRegionAddressList) {
                    Pointer ptr = UnidbgPointer.pointer(emulator, pc);
                    assert ptr != null;
                    byte[] code = ptr.getByteArray(0, 4);
                    Instruction instruction = createDisassembler().disasm(code, pc, 1)[0];
                    switch (instruction.getMnemonic()) {
                        case "stxr":
                        case "stlxr":
                        case "stxrh":
                        case "stlxrh":
                            foundAddress = pc;
                            break;
                    }
                    builder.append(String.format("0x%x: %s%n", instruction.getAddress(), instruction));
                }
                if (foundAddress == 0) {
                    log.info("CodeHookNotifier.onSoftwareStep: \n{}", builder);
                } else {
                    resetRegionInfo();
                    final long breakAddress = foundAddress + 4;
                    for (int i = 0; i < breakpoints.length; i++) {
                        if (breakpoints[i] == null) {
                            final int n = i;
                            visitorStack.push(new ExceptionVisitor() {
                                @Override
                                public boolean onException(Hypervisor hypervisor, int ec, long address) {
                                    if (ec == EC_BREAKPOINT) {
                                        callback.notifyCallback(address);
                                    }
                                    breakpoints[n] = null;
                                    hypervisor.disable_hw_breakpoint(n);
                                    callback.onEscapeSuccess();
                                    step();
                                    return true;
                                }
                            });
                            callback.notifyCallback(address);
                            HypervisorBreakPoint bp = new HypervisorBreakPoint(n, breakAddress, null);
                            bp.install(hypervisor);
                            breakpoints[n] = bp;
                            hypervisor.enable_single_step(false);
                            hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
                            return;
                        }
                    }
                    log.warn("No more BKPs: {}", breakpoints.length);
                }
            }
            callback.notifyCallback(address);
            hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
        }
    }

    private class CodeHookNotifier implements UnHook, ExclusiveMonitorCallback {
        private final CodeHook callback;
        private final long begin;
        private final long end;
        private final Object user;
        public CodeHookNotifier(CodeHook callback, long begin, long end, Object user) {
            this.callback = callback;
            this.begin = begin;
            this.end = end;
            this.user = user;
        }
        @Override
        public void onEscapeSuccess() {
            step();
        }
        @Override
        public void notifyCallback(long address) {
            if (begin >= end ||
                    (address >= begin && address < end)) {
                callback.hook(HypervisorBackend64.this, address, 4, user);
            }
        }
        @Override
        public void unhook() {
            exclusiveMonitorEscaper = null;
        }
    }

    private ExclusiveMonitorEscaper exclusiveMonitorEscaper;

    @Override
    public void hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        if (exclusiveMonitorEscaper != null) {
            throw new IllegalStateException();
        }
        CodeHookNotifier codeHookNotifier = new CodeHookNotifier(callback, begin, end, user_data);
        this.exclusiveMonitorEscaper = new ExclusiveMonitorEscaper(codeHookNotifier);
        callback.onAttach(codeHookNotifier);
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
            if (debugCallback != null) {
                debugCallback.onBreak(this, address, INS_SIZE, debugUserData);
            } else {
                int status = (int) (esr & 0x3f);
                interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, status);
            }
        } else {
            hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
        }
    }

    private boolean handleCommRead(long vaddr, long elr, int accessSize) {
        Pointer pointer = UnidbgPointer.pointer(emulator, vaddr);
        assert pointer != null;
        Pointer pc = UnidbgPointer.pointer(emulator, elr);
        assert pc != null;
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
            case 0x38: // uint64_t max memory size */
            case 0x40:
            case 0x58: {
                Operand operand = op[0];
                OpValue value = operand.getValue();
                reg_write(insn.mapToUnicornReg(value.getReg()), 0x0L);
                hypervisor.reg_set_elr_el1(elr + 4);
                return true;
            }
            case 0x48:
            case 0x4c:
            case 0x50:
            case 0x60:
            case 0x64:
            case 0x90: {
                Operand operand = op[0];
                OpValue value = operand.getValue();
                reg_write(insn.mapToUnicornReg(value.getReg()), 0x0);
                hypervisor.reg_set_elr_el1(elr + 4);
                return true;
            }
            case 0x22: // uint8_t number of configured CPUs
            case 0x34: // uint8_t number of active CPUs (hw.activecpu)
            case 0x35: // uint8_t number of physical CPUs (hw.physicalcpu_max)
            case 0x36: { // uint8_t number of logical CPUs (hw.logicalcpu_max)
                Operand operand = op[0];
                OpValue value = operand.getValue();
                reg_write(insn.mapToUnicornReg(value.getReg()), 1);
                hypervisor.reg_set_elr_el1(elr + 4);
                return true;
            }
            default:
                throw new UnsupportedOperationException("vaddr=0x" + Long.toHexString(vaddr) + ", offset=0x" + Long.toHexString(offset));
        }
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
            switch (regId) {
                case Arm64Const.UC_ARM64_REG_X0:
                case Arm64Const.UC_ARM64_REG_X1:
                case Arm64Const.UC_ARM64_REG_X2:
                case Arm64Const.UC_ARM64_REG_X3:
                case Arm64Const.UC_ARM64_REG_X4:
                case Arm64Const.UC_ARM64_REG_X5:
                case Arm64Const.UC_ARM64_REG_X6:
                case Arm64Const.UC_ARM64_REG_X7:
                case Arm64Const.UC_ARM64_REG_X8:
                case Arm64Const.UC_ARM64_REG_X9:
                case Arm64Const.UC_ARM64_REG_X10:
                case Arm64Const.UC_ARM64_REG_X11:
                case Arm64Const.UC_ARM64_REG_X12:
                case Arm64Const.UC_ARM64_REG_X13:
                case Arm64Const.UC_ARM64_REG_X14:
                case Arm64Const.UC_ARM64_REG_X15:
                case Arm64Const.UC_ARM64_REG_X16:
                case Arm64Const.UC_ARM64_REG_X17:
                case Arm64Const.UC_ARM64_REG_X18:
                case Arm64Const.UC_ARM64_REG_X19:
                case Arm64Const.UC_ARM64_REG_X20:
                case Arm64Const.UC_ARM64_REG_X21:
                case Arm64Const.UC_ARM64_REG_X22:
                case Arm64Const.UC_ARM64_REG_X23:
                case Arm64Const.UC_ARM64_REG_X24:
                case Arm64Const.UC_ARM64_REG_X25:
                case Arm64Const.UC_ARM64_REG_X26:
                case Arm64Const.UC_ARM64_REG_X27:
                case Arm64Const.UC_ARM64_REG_X28:
                    hypervisor.reg_write64(regId - Arm64Const.UC_ARM64_REG_X0, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_W0:
                case Arm64Const.UC_ARM64_REG_W1:
                case Arm64Const.UC_ARM64_REG_W2:
                case Arm64Const.UC_ARM64_REG_W3:
                case Arm64Const.UC_ARM64_REG_W4:
                case Arm64Const.UC_ARM64_REG_W5:
                case Arm64Const.UC_ARM64_REG_W6:
                case Arm64Const.UC_ARM64_REG_W7:
                case Arm64Const.UC_ARM64_REG_W8:
                case Arm64Const.UC_ARM64_REG_W9:
                case Arm64Const.UC_ARM64_REG_W10:
                case Arm64Const.UC_ARM64_REG_W11:
                case Arm64Const.UC_ARM64_REG_W12:
                case Arm64Const.UC_ARM64_REG_W13:
                case Arm64Const.UC_ARM64_REG_W14:
                case Arm64Const.UC_ARM64_REG_W15:
                case Arm64Const.UC_ARM64_REG_W16:
                case Arm64Const.UC_ARM64_REG_W17:
                case Arm64Const.UC_ARM64_REG_W18:
                case Arm64Const.UC_ARM64_REG_W19:
                case Arm64Const.UC_ARM64_REG_W20:
                case Arm64Const.UC_ARM64_REG_W21:
                case Arm64Const.UC_ARM64_REG_W22:
                case Arm64Const.UC_ARM64_REG_W23:
                case Arm64Const.UC_ARM64_REG_W24:
                case Arm64Const.UC_ARM64_REG_W25:
                case Arm64Const.UC_ARM64_REG_W26:
                case Arm64Const.UC_ARM64_REG_W27:
                case Arm64Const.UC_ARM64_REG_W28:
                case Arm64Const.UC_ARM64_REG_W29:
                case Arm64Const.UC_ARM64_REG_W30:
                    hypervisor.reg_write64(regId - Arm64Const.UC_ARM64_REG_W0, value.longValue());
                    break;
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
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        try {
            switch (regId) {
                case Arm64Const.UC_ARM64_REG_X0:
                case Arm64Const.UC_ARM64_REG_X1:
                case Arm64Const.UC_ARM64_REG_X2:
                case Arm64Const.UC_ARM64_REG_X3:
                case Arm64Const.UC_ARM64_REG_X4:
                case Arm64Const.UC_ARM64_REG_X5:
                case Arm64Const.UC_ARM64_REG_X6:
                case Arm64Const.UC_ARM64_REG_X7:
                case Arm64Const.UC_ARM64_REG_X8:
                case Arm64Const.UC_ARM64_REG_X9:
                case Arm64Const.UC_ARM64_REG_X10:
                case Arm64Const.UC_ARM64_REG_X11:
                case Arm64Const.UC_ARM64_REG_X12:
                case Arm64Const.UC_ARM64_REG_X13:
                case Arm64Const.UC_ARM64_REG_X14:
                case Arm64Const.UC_ARM64_REG_X15:
                case Arm64Const.UC_ARM64_REG_X16:
                case Arm64Const.UC_ARM64_REG_X17:
                case Arm64Const.UC_ARM64_REG_X18:
                case Arm64Const.UC_ARM64_REG_X19:
                case Arm64Const.UC_ARM64_REG_X20:
                case Arm64Const.UC_ARM64_REG_X21:
                case Arm64Const.UC_ARM64_REG_X22:
                case Arm64Const.UC_ARM64_REG_X23:
                case Arm64Const.UC_ARM64_REG_X24:
                case Arm64Const.UC_ARM64_REG_X25:
                case Arm64Const.UC_ARM64_REG_X26:
                case Arm64Const.UC_ARM64_REG_X27:
                case Arm64Const.UC_ARM64_REG_X28:
                    return hypervisor.reg_read64(regId - Arm64Const.UC_ARM64_REG_X0);
                case Arm64Const.UC_ARM64_REG_W0:
                case Arm64Const.UC_ARM64_REG_W1:
                case Arm64Const.UC_ARM64_REG_W2:
                case Arm64Const.UC_ARM64_REG_W3:
                case Arm64Const.UC_ARM64_REG_W4:
                case Arm64Const.UC_ARM64_REG_W5:
                case Arm64Const.UC_ARM64_REG_W6:
                case Arm64Const.UC_ARM64_REG_W7:
                case Arm64Const.UC_ARM64_REG_W8:
                case Arm64Const.UC_ARM64_REG_W9:
                case Arm64Const.UC_ARM64_REG_W10:
                case Arm64Const.UC_ARM64_REG_W11:
                case Arm64Const.UC_ARM64_REG_W12:
                case Arm64Const.UC_ARM64_REG_W13:
                case Arm64Const.UC_ARM64_REG_W14:
                case Arm64Const.UC_ARM64_REG_W15:
                case Arm64Const.UC_ARM64_REG_W16:
                case Arm64Const.UC_ARM64_REG_W17:
                case Arm64Const.UC_ARM64_REG_W18:
                case Arm64Const.UC_ARM64_REG_W19:
                case Arm64Const.UC_ARM64_REG_W20:
                case Arm64Const.UC_ARM64_REG_W21:
                case Arm64Const.UC_ARM64_REG_W22:
                case Arm64Const.UC_ARM64_REG_W23:
                case Arm64Const.UC_ARM64_REG_W24:
                case Arm64Const.UC_ARM64_REG_W25:
                case Arm64Const.UC_ARM64_REG_W26:
                case Arm64Const.UC_ARM64_REG_W27:
                case Arm64Const.UC_ARM64_REG_W28:
                case Arm64Const.UC_ARM64_REG_W29:
                case Arm64Const.UC_ARM64_REG_W30:
                    return (int) (hypervisor.reg_read64(regId - Arm64Const.UC_ARM64_REG_W0) & 0xffffffffL);
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
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble("brk #" + svcNumber);
            return encoded.getMachineCode();
        }
    }

    @Override
    public synchronized void destroy() throws BackendException {
        super.destroy();

        IOUtils.close(disassembler);
        disassembler = null;
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
}
