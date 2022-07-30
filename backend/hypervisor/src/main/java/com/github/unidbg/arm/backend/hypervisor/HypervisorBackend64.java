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
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.DebugHook;
import com.github.unidbg.arm.backend.HypervisorBackend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

import java.util.Stack;

public class HypervisorBackend64 extends HypervisorBackend {

    private static final Log log = LogFactory.getLog(HypervisorBackend64.class);

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
        hypervisor.enable_single_step(true);
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
                hypervisor.install_hw_breakpoint(i, address);
                HypervisorBreakPoint bp = new HypervisorBreakPoint(address, callback);
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
                    log.debug("handleDataAbort srt=" + srt + ", sf=" + sf + ", accessSize=" + accessSize);
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
                log.warn("handleUnknownException ec=0x" + Integer.toHexString(ec) + ", virtualAddress=0x" + Long.toHexString(virtualAddress) + ", esr=0x" + Long.toHexString(esr) + ", far=0x" + Long.toHexString(far));
                break;
        }
    }

    @Override
    public boolean handleException(long esr, long far, final long elr, long cpsr) {
        int ec = (int) ((esr >> 26) & 0x3f);
        if (log.isDebugEnabled()) {
            log.debug("handleException syndrome=0x" + Long.toHexString(esr) + ", far=0x" + Long.toHexString(far) + ", elr=0x" + Long.toHexString(elr) + ", ec=0x" + Integer.toHexString(ec) + ", cpsr=0x" + Long.toHexString(cpsr));
        }
        while (!visitorStack.isEmpty()) {
            visitorStack.pop().onException();
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
                onBreakpoint(esr, elr);
                for (int i = 0; i < breakpoints.length; i++) {
                    HypervisorBreakPoint bp = breakpoints[i];
                    if (bp != null && bp.address == elr) {
                        hypervisor.disable_hw_breakpoint(i);
                        visitorStack.push(new ExceptionVisitor(i) {
                            @Override
                            public void onException() {
                                if (breakpoints[super.n] != null) {
                                    hypervisor.install_hw_breakpoint(super.n, elr);
                                }
                            }
                        });
                        step();
                        break;
                    }
                }
                return true;
            }
            case EC_WATCHPOINT: {
                onWatchpoint(esr, far);
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
                    log.debug("handle EC_DATAABORT isv=" + isv + ", isWrite=" + isWrite + ", s1ptw=" + s1ptw + ", len=" + len + ", srt=" + srt + ", dfsc=0x" + Integer.toHexString(dfsc) + ", vaddr=0x" + Long.toHexString(far));
                }
                if (dfsc == 0x00 && emulator.getFamily() == Family.iOS) {
                    int accessSize = isv ? 1 << sas : 0;
                    return handleCommRead(far, elr, accessSize);
                }
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec) + ", dfsc=0x" + Integer.toHexString(dfsc));
            }
            default:
                log.warn("handleException ec=0x" + Integer.toHexString(ec));
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

    private void onWatchpoint(long esr, long address) {
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
            log.debug("onWatchpoint write=" + write + ", address=0x" + Long.toHexString(address) + ", cm=" + cm + ", wpt=" + wpt + ", wptv=" + wptv + ", status=0x" + Integer.toHexString(status));
        }
        boolean hit = false;
        for (int i = 0; i < watchpoints.length; i++) {
            if (watchpoints[i] != null && watchpoints[i].contains(address, write)) {
                hit = true;
                if (watchpoints[i].onHit(this, address, write)) {
                    installRestoreWatchpoint(i, watchpoints[i]);
                    return;
                }
            }
        }
        if (!hit) {
            interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, status);
        }
    }

    private void installRestoreWatchpoint(int n, final HypervisorWatchpoint watchpoint) {
        hypervisor.disable_watchpoint(n);
        visitorStack.push(new ExceptionVisitor(n) {
            @Override
            public void onException() {
                watchpoint.install(hypervisor);
            }
        });
        step();
    }

    private void onBreakpoint(long esr, long elr) {
        if (debugCallback != null) {
            debugCallback.onBreak(this, elr, INS_SIZE, debugUserData);
        } else {
            int status = (int) (esr & 0x3f);
            interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, status);
        }
    }

    private class CodeHookNotifier implements UnHook {
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
        public void onSoftwareStep(long address) {
            if (begin >= end ||
                    (address >= begin && address < end)) {
                callback.hook(HypervisorBackend64.this, address, 4, user);
            }
        }
        @Override
        public void unhook() {
            codeHookNotifier = null;
        }
    }

    private CodeHookNotifier codeHookNotifier;

    /**
     * The local exclusive monitor gets cleared on every exception return, that is, on execution of the ERET instruction.
     *
     * from: <a href="https://xen-devel.narkive.com/wQw4F6GV/xen-arm-software-step-armv8-pc-stuck-on-instruction">...</a>
     * LDAXR sets the 'exclusive monitor' and STXR only succeeds if the exclusive
     * monitor is still set. If another CPU accesses the memory protected by the
     * exclusive monitor, the monitor is cleared. This is how the spinlock code knows
     * it has to re-read its value and try to take the lock again.
     * Changing exception level also clears the exclusive monitor, so taking
     * single-step exception between a LDAXR/STXR pair means the loop has to be retried.
     */
    @Override
    public void hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        if (codeHookNotifier != null) {
            throw new IllegalStateException();
        }
        codeHookNotifier = new CodeHookNotifier(callback, begin, end, user_data);
        hypervisor.enable_single_step(true);
        callback.onAttach(codeHookNotifier);
    }

    private void onSoftwareStep(long esr, long address, long spsr) {
        if (codeHookNotifier != null) {
            codeHookNotifier.onSoftwareStep(address);
            hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
            return;
        }

        if (--singleStep == 0) {
            if (debugCallback != null) {
                debugCallback.onBreak(this, address, INS_SIZE, debugUserData);
            } else {
                int status = (int) (esr & 0x3f);
                interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, status);
            }
        } else if (singleStep > 0) {
            hypervisor.reg_set_spsr_el1(spsr | Hypervisor.PSTATE$SS);
        } else {
            hypervisor.enable_single_step(false);
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
            log.debug("handleCommRead vaddr=0x" + Long.toHexString(vaddr) + ", elr=0x" + Long.toHexString(elr) + ", asm=" + insn);
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
