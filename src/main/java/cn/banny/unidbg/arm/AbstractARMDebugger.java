package cn.banny.unidbg.arm;

import capstone.Capstone;
import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.debugger.DebugListener;
import cn.banny.unidbg.debugger.Debugger;
import cn.banny.utils.Hex;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

abstract class AbstractARMDebugger implements Debugger {

    private static final Log log = LogFactory.getLog(AbstractARMDebugger.class);

    final Map<Long, Module> breakMap = new HashMap<>();

    final Emulator emulator;

    AbstractARMDebugger(Emulator emulator) {
        this.emulator = emulator;
    }

    @Override
    public final void addBreakPoint(Module module, String symbol) {
        try {
            Symbol sym = module.findSymbolByName(symbol, false);
            if (sym == null) {
                throw new IllegalStateException("find symbol failed: " + symbol);
            }
            addBreakPoint(module, sym.getValue());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public final void addBreakPoint(Module module, long offset) {
        long address = (module == null ? offset : module.base + offset) & (~1);
        if (log.isDebugEnabled()) {
            log.debug("addBreakPoint address=0x" + Long.toHexString(address));
        }
        breakMap.put(address, module);
    }

    private final List<CodeHistory> historyList = new ArrayList<>(15);

    private DebugListener listener;

    @Override
    public void setDebugListener(DebugListener listener) {
        this.listener = listener;
    }

    @Override
    public final void hook(Unicorn u, long address, int size, Object user) {
        Emulator emulator = (Emulator) user;

        while (historyList.size() > 10) {
            historyList.remove(0);
        }
        CodeHistory history = new CodeHistory(address, size, ARM.isThumb(u));
        historyList.add(history);

        if (singleStep >= 0) {
            singleStep--;
        }

        try {
            if (breakMap.containsKey(address)) {
                loop(emulator, u, address, size);
            } else if (singleStep == 0) {
                loop(emulator, u, address, size);
            } else if (breakMnemonic != null) {
                Capstone.CsInsn ins = history.disassemble(emulator);
                if (breakMnemonic.equals(ins.mnemonic)) {
                    breakMnemonic = null;
                    loop(emulator, u, address, size);
                }
            } else if (listener != null && listener.canDebug(emulator, history)) {
                loop(emulator, u, address, size);
            }
        } catch (Exception e) {
            log.warn("process hook failed", e);
        }
    }

    @Override
    public void debug() {
        Unicorn unicorn = emulator.getUnicorn();
        long address;
        if (emulator.getPointerSize() == 4) {
            address = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
        } else {
            address = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
        }
        try {
            loop(emulator, unicorn, address, 0);
        } catch (Exception e) {
            log.warn("debug failed", e);
        }
    }

    int singleStep;

    String breakMnemonic;

    abstract void loop(Emulator emulator, Unicorn u, long address, int size) throws Exception;

    final void dumpMemory(Pointer pointer, int _length, String label, boolean nullTerminated) {
        if (nullTerminated) {
            long addr = 0;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            boolean foundTerminated = false;
            while (true) {
                byte[] data = pointer.getByteArray(addr, 0x100);
                int length = data.length;
                for (int i = 0; i < data.length; i++) {
                    if (data[i] == 0) {
                        length = i;
                        break;
                    }
                }
                baos.write(data, 0, length);
                addr += length;

                if (length < data.length) { // reach zero
                    foundTerminated = true;
                    break;
                }

                if (baos.size() > 0x10000) { // 64k
                    break;
                }
            }

            if (foundTerminated) {
                Inspector.inspect(baos.toByteArray(), baos.size() >= 1024 ? (label + ", hex=" + Hex.encodeHexString(baos.toByteArray())) : label);
            } else {
                Inspector.inspect(pointer.getByteArray(0, _length), label + ", find NULL-terminated failed");
            }
        } else {
            byte[] data = pointer.getByteArray(0, _length);
            Inspector.inspect(data, data.length >= 1024 ? (label + ", hex=" + Hex.encodeHexString(data)) : label);
        }
    }

    /**
     * @return next address
     */
    final long disassemble(Emulator emulator, long address, int size, boolean thumb) {
        long next = 0;
        boolean on = false;
        StringBuilder sb = new StringBuilder();
        for (CodeHistory history : historyList) {
            if (history.address == address) {
                sb.append("=> *");
                on = true;
            } else {
                sb.append("    ");
                if (on) {
                    next = history.address;
                    on = false;
                }
            }
            Capstone.CsInsn ins = history.disassemble(emulator);
            sb.append(ARM.assembleDetail(emulator.getMemory(), ins, history.address, history.thumb, on ? '*' : ' ')).append('\n');
        }
        long nextAddr = address + size;
        Capstone.CsInsn[] insns = emulator.disassemble(nextAddr, 4 * 10, 10);
        for (Capstone.CsInsn ins : insns) {
            if (nextAddr == address) {
                sb.append("=> *");
                on = true;
            } else {
                sb.append("    ");
                if (on) {
                    next = nextAddr;
                    on = false;
                }
            }
            sb.append(ARM.assembleDetail(emulator.getMemory(), ins, nextAddr, thumb, on ? '*' : ' ')).append('\n');
            nextAddr += ins.size;
        }
        System.out.println(sb);
        return next;
    }

}
