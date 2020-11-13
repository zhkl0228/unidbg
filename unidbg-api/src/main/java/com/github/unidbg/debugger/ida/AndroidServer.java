package com.github.unidbg.debugger.ida;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.debugger.AbstractDebugServer;
import com.github.unidbg.debugger.ida.event.AttachExecutableEvent;
import com.github.unidbg.debugger.ida.event.DetachEvent;
import com.github.unidbg.debugger.ida.event.LoadExecutableEvent;
import com.github.unidbg.debugger.ida.event.LoadModuleEvent;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

public class AndroidServer extends AbstractDebugServer implements ModuleListener {

    private static final Log log = LogFactory.getLog(AndroidServer.class);

    private final byte protocolVersion;

    public AndroidServer(Emulator<?> emulator, byte protocolVersion) {
        super(emulator);
        this.protocolVersion = protocolVersion;
        emulator.getMemory().addModuleListener(this);
    }

    private void notifyDebugEvent() {
        sendAck((byte) 0x1);
    }

    private void sendAck(byte... bytes) {
        sendPacket(0x0, bytes);
    }

    private void sendPacket(int type, byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocate(data.length + 5);
        buffer.putInt(data.length);
        buffer.put((byte) type);
        buffer.put(data);
        sendData(buffer.array());
    }

    private void sendProcessWillTerminated(int exitStatus) {
        ByteBuffer buffer = ByteBuffer.allocate(0x20);
        buffer.put(Utils.pack_dd(0x2));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dd(0x0));
        buffer.put(Utils.pack_dd(0x1));
        buffer.put(Utils.pack_dd(0x0));
        buffer.put(Utils.pack_dd(exitStatus));
        sendPacket(0x4, Utils.flipBuffer(buffer));
    }

    @Override
    protected void onServerStart() {
    }

    @Override
    public void onLoaded(Emulator<?> emulator, Module module) {
        if (log.isDebugEnabled()) {
            log.debug("onLoaded module=" + module);
        }
    }

    @Override
    protected void processInput(ByteBuffer input) {
        input.flip();

        while (input.hasRemaining()) {
            int length = input.getInt();
            int type = input.get() & 0xff;
            if (length > input.remaining()) {
                throw new IllegalStateException("processInput length=" + length + ", type=0x" + Integer.toHexString(type));
            }

            byte[] data = new byte[length];
            input.get(data);
            processCommand(type, data);
        }

        input.clear();
    }

    private void processCommand(int type, byte[] data) {
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(data, "processCommand type=0x" + Integer.toHexString(type)));
        }

        if (type == 0x0 && data.length == 0) { // ack
            return;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);
        switch (type) {
            case 0x0:
                notifyDebugEvent();
                break;
            case 0x5: {
                ackDebuggerEvent();
                break;
            }
            case 0xa: {
                long value = Utils.unpack_dd(buffer);
                long b = Utils.unpack_dd(buffer);
                if (log.isDebugEnabled()) {
                    log.debug("processCommand value=0x" + Long.toHexString(value) + ", b=" + b);
                }
                sendAck((byte) 0x5);
                break;
            }
            case 0xb: {
                notifyDebuggerDetached();
                break;
            }
            case 0xc: {
                requestRunningProcesses();
                break;
            }
            case 0xe:
                requestTerminateProcess();
                break;
            case 0xf: {
                requestAttach(buffer);
                break;
            }
            case 0x10:
                requestDetach();
                break;
            case 0x11:
                syncDebuggerEvent(buffer);
                break;
            case 0x12:
                requestPauseProcess();
                break;
            case 0x13:
                requestSymbols(buffer);
                break;
            case 0x14:
                onDebuggerEvent(buffer);
                break;
            case 0x18:
                requestMemoryRegions(buffer);
                break;
            case 0x19:
                requestReadMemory(buffer);
                break;
            case 0x1b:
                requestBreakPointAction(buffer);
                break;
            case 0x1f:
                requestReadRegisters(buffer);
                break;
            case 0x20:
                requestResetProgramCounter(buffer);
                break;
            case 0x22:
                parseSignal(buffer);
                break;
            default:
                log.warn(Inspector.inspectString(data, "Not handler command type=0x" + Integer.toHexString(type)));
                sendAck();
                break;
        }
    }

    private void requestResetProgramCounter(ByteBuffer buffer) {
        long tid = Utils.unpack_dd(buffer);
        long b1 = Utils.unpack_dd(buffer);
        long b2 = Utils.unpack_dd(buffer);
        long pc = Utils.unpack_dq(buffer);
        if (log.isDebugEnabled()) {
            log.debug("requestResetProgramCounter tid=" + tid + ", b1=" + b1 + ", b2=" + b2 + ", pc=0x" + Long.toHexString(pc));
        }
        notifyDebugEvent();
    }

    private void requestPauseProcess() {
        if (log.isDebugEnabled()) {
            log.debug("requestPauseProcess");
        }
        sendAck();
    }

    private int processExitStatus;

    private void ackDebuggerEvent() {
        if (log.isDebugEnabled()) {
            log.debug("ackDebuggerEvent");
        }
    }

    private void notifyDebuggerDetached() {
        if (log.isDebugEnabled()) {
            log.debug("notifyDebuggerDetached");
        }

        sendAck();
        shutdownServer();
        if (processExitStatus != 0) {
            System.exit(processExitStatus);
        } else {
            resumeRun();
        }
    }

    private void requestBreakPointAction(ByteBuffer buffer) {
        long action = Utils.unpack_dd(buffer); // 0表示删除断点，1表示设置断点
        if (action == 0) {
            long b2 = Utils.unpack_dd(buffer);
            long address = Utils.unpack_dq(buffer);
            long size = Utils.unpack_dd(buffer);
            byte[] backup = new byte[(int) size];
            buffer.get(backup);
            long b3 = Utils.unpack_dd(buffer);
            long value = Utils.unpack_dq(buffer);

            if (log.isDebugEnabled()) {
                log.debug(Inspector.inspectString(backup, "requestBreakPointAction action=" + action + ", b2=" + b2 + ", address=0x" + Long.toHexString(address) +
                        ", size=" + size + ", b3=" + b3 + ", value=0x" + Long.toHexString(value)));
            }

            address -= 1;
            removeBreakPoint(address);

            ByteBuffer newBuf = ByteBuffer.allocate(0x10);
            newBuf.put(Utils.pack_dd(0x1));
            newBuf.put(Utils.pack_dd(0x1));
            newBuf.put(Utils.pack_dd(0x0));
            sendAck(Utils.flipBuffer(newBuf));
        } else if (action == 1) {
            long b2 = Utils.unpack_dd(buffer);
            long address = Utils.unpack_dq(buffer);
            long b3 = Utils.unpack_dd(buffer);
            long size = Utils.unpack_dd(buffer);
            long value = Utils.unpack_dq(buffer);

            if (log.isDebugEnabled()) {
                log.debug("requestBreakPointAction action=" + action + ", b2=" + b2 + ", address=0x" + Long.toHexString(address) + ", b3=" + b3 +
                        ", size=" + size + ", value=0x" + Long.toHexString(value));
            }

            address -= 1;
            addBreakPoint(address);

            ByteBuffer newBuf = ByteBuffer.allocate(0x10);
            newBuf.put(Utils.pack_dd(0x1));
            newBuf.put(Utils.pack_dd(0x1));
            newBuf.put(Utils.pack_dd(0x0));
            Backend backend = emulator.getBackend();
            byte[] data = backend.mem_read(address & (~1), size);
            newBuf.put(Utils.pack_dd(data.length));
            newBuf.put(data);
            sendAck(Utils.flipBuffer(newBuf));
        } else {
            throw new UnsupportedOperationException("action=" + action);
        }
    }

    private static final int TERMINATE_PROCESS_STATUS = 9;

    private void requestTerminateProcess() {
        if (log.isDebugEnabled()) {
            log.debug("requestTerminateProcess");
        }

        notifyDebugEvent();
        sendProcessWillTerminated(TERMINATE_PROCESS_STATUS);
    }

    private void requestDetach() {
        if (log.isDebugEnabled()) {
            log.debug("requestDetach");
        }

        eventQueue.add(new DetachEvent());
        notifyDebugEvent();
    }

    private void requestMemoryRegions(ByteBuffer buffer) {
        if (log.isDebugEnabled()) {
            log.debug("requestMemoryRegions buffer=" + buffer);
        }

        Memory memory = emulator.getMemory();
        Collection<Module> modules = memory.getLoadedModules();
        List<MemRegion> list = new ArrayList<>(modules.size());
        for (Module module : modules) {
            list.addAll(module.getRegions());
        }
        SvcMemory svcMemory = emulator.getSvcMemory();
        list.add(MemRegion.create(svcMemory.getBase(), svcMemory.getSize(), UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC, "[svc]"));
        list.add(MemRegion.create(memory.getStackBase() - memory.getStackSize(), memory.getStackSize(), UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE, "[stack]"));
        Collections.sort(list);

        ByteBuffer newBuf = ByteBuffer.allocate(0x100 * list.size());
        newBuf.put(Utils.pack_dd(0x5));
        newBuf.put(Utils.pack_dd(list.size()));
        for (MemRegion region : list) {
            newBuf.put(Utils.pack_dq(0x1));
            newBuf.put(Utils.pack_dq(region.begin + 1));
            long size = region.end - region.begin;
            newBuf.put(Utils.pack_dq(size + 1));
            int mask = 1 << 4; // data
            if ((region.perms & UnicornConst.UC_PROT_READ) != 0) {
                mask |= (1 << 2);
            }
            if ((region.perms & UnicornConst.UC_PROT_WRITE) != 0) {
                mask |= (1 << 1);
            }
            if ((region.perms & UnicornConst.UC_PROT_EXEC) != 0) {
                mask |= 1;
            }
            newBuf.put((byte) mask);
            Utils.writeCString(newBuf, region.getName());
            newBuf.put((byte) 0);
        }
        sendAck(Utils.flipBuffer(newBuf));
    }

    private void requestReadRegisters(ByteBuffer buffer) {
        long tid = Utils.unpack_dd(buffer);
        long b = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("requestReadRegisters tid=0x" + Long.toHexString(tid) + ", b=" + b);
        }

        if (emulator.is32Bit()) {
            Arm32RegisterContext context = emulator.getContext();
            ByteBuffer newBuf = ByteBuffer.allocate(0x100);
            newBuf.put(Utils.pack_dd(0x1));
            for (int value : Arrays.asList(context.getR0Int(),
                    context.getR1Int(), context.getR2Int(),
                    context.getR3Int(), context.getR4Int(),
                    context.getR5Int(), context.getR6Int(),
                    context.getR7Int(), context.getR8Int(),
                    context.getR9Int(), context.getR10Int(),
                    context.getInt(ArmConst.UC_ARM_REG_FP),
                    context.getInt(ArmConst.UC_ARM_REG_IP),
                    context.getInt(ArmConst.UC_ARM_REG_SP),
                    context.getInt(ArmConst.UC_ARM_REG_LR),
                    context.getInt(ArmConst.UC_ARM_REG_PC),
                    context.getInt(ArmConst.UC_ARM_REG_CPSR))) {
                newBuf.put(Utils.pack_dd(0x1));
                newBuf.put(Utils.pack_dq((value & 0xffffffffL) + 1));
            }
            sendAck(Utils.flipBuffer(newBuf));
        } else {
            Arm64RegisterContext context = emulator.getContext();
            ByteBuffer newBuf = ByteBuffer.allocate(0x200);
            newBuf.put(Utils.pack_dd(0x1));
            for (int i = 0; i < 29; i++) {
                int regId = Arm64Const.UC_ARM64_REG_X0 + i;
                newBuf.put(Utils.pack_dd(0x1));
                newBuf.put(Utils.pack_dq(context.getLong(regId) + 1));
            }
            for (long value : Arrays.asList(context.getLong(Arm64Const.UC_ARM64_REG_X29),
                    context.getLong(Arm64Const.UC_ARM64_REG_X30),
                    context.getLong(Arm64Const.UC_ARM64_REG_SP),
                    context.getLong(Arm64Const.UC_ARM64_REG_PC),
                    context.getLong(Arm64Const.UC_ARM64_REG_NZCV))) {
                newBuf.put(Utils.pack_dd(0x1));
                newBuf.put(Utils.pack_dq(value + 1));
            }
            sendAck(Utils.flipBuffer(newBuf));
        }
    }

    private void requestSymbols(ByteBuffer buffer) {
        if (log.isDebugEnabled()) {
            log.debug("requestSymbols buffer=" + buffer);
        }
        sendAck();
    }

    private void requestReadMemory(ByteBuffer buffer) {
        long address = Utils.unpack_dq(buffer);
        long size = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("requestReadMemory address=0x" + Long.toHexString(address) + ", size=" + size);
        }
        try {
            Backend backend = emulator.getBackend();
            byte[] data = backend.mem_read(address - 1, size);
            ByteBuffer newBuf = ByteBuffer.allocate(data.length + 0x10);
            newBuf.put(Utils.pack_dd(size));
            newBuf.put(data);
            sendAck(Utils.flipBuffer(newBuf));
        } catch (BackendException e) {
            if (log.isDebugEnabled()) {
                log.debug("read memory failed: address=0x" + Long.toHexString(address), e);
            }
            sendAck();
        }
    }

    private void parseSignal(ByteBuffer buffer) {
        long size = Utils.unpack_dd(buffer);
        for (int i = 0; i < size; i++) {
            long index = Utils.unpack_dd(buffer);
            long mask = Utils.unpack_dd(buffer);
            String sig = Utils.readCString(buffer);
            String desc = Utils.readCString(buffer);
            if (log.isDebugEnabled()) {
                log.debug("signal index=" + index + ", mask=0x" + Long.toHexString(mask) + ", sig=" + sig + ", desc=" + desc);
            }
        }
        sendAck();
    }

    private final Queue<DebuggerEvent> eventQueue = new LinkedBlockingQueue<>();

    private void syncDebuggerEvent(ByteBuffer buffer) {
        long b = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("syncDebuggerEvent b=" + b);
        }

        DebuggerEvent event = eventQueue.poll();
        if (event == null) {
            sendAck((byte) 0x0);
        } else {
            byte[] packet = event.pack(emulator);
            sendAck(packet);
        }
    }

    private void onDebuggerEvent(ByteBuffer buffer) {
        int type = (int) Utils.unpack_dd(buffer);
        switch (type) {
            case 0x1: // notify attach success
            case 0x400: // notify continue run
                notifyProcessEvent(buffer, type);
                break;
            case 0x10:
                notifyProcessSingleStep(buffer);
                break;
            case 0x2:
                notifyProcessExit(buffer);
                break;
            case 0x80:
                notifyLoadModule(buffer);
                break;
            case 0x800:
                notifyProcessStatus(buffer);
                break;
            default:
                log.warn("onDebuggerEvent type=0x" + Integer.toHexString(type));
                break;
        }
        notifyDebugEvent();
    }

    private void notifyProcessSingleStep(ByteBuffer buffer) {
        long pid = Utils.unpack_dd(buffer);
        long tid = Utils.unpack_dd(buffer);
        long pc = Utils.unpack_dq(buffer);
        if (log.isDebugEnabled()) {
            log.debug("notifyProcessSingleStep pid=" + pid + ", tid=" + tid + ", pc=0x" + Long.toHexString(pc));
        }

        resumeRun();
    }

    private void notifyProcessStatus(ByteBuffer buffer) {
        long pid = Utils.unpack_dd(buffer);
        long tid = Utils.unpack_dd(buffer);
        long b1 = Utils.unpack_dd(buffer);
        long b2 = Utils.unpack_dd(buffer);
        long b3 = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("notifyProcessStatus pid=" + pid + ", tid=" + tid + ", b1=" + b1 +
                    ", b2=" + b2 + ", b3=" + b3);
        }
    }

    private void notifyProcessExit(ByteBuffer buffer) {
        long pid = Utils.unpack_dd(buffer);
        long tid = Utils.unpack_dd(buffer);
        long b1 = Utils.unpack_dd(buffer);
        long b2 = Utils.unpack_dd(buffer);
        long b3 = Utils.unpack_dd(buffer);
        long exitStatus = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("notifyProcessExit pid=" + pid + ", tid=" + tid + ", b1=" + b1 +
                    ", b2=" + b2 + ", b3=" + b3 + ", exitStatus=" + exitStatus);
        }
        this.processExitStatus = (int) exitStatus;
    }

    /**
     * @param type 0x1表示attach成功，0x400表示要求继续执行
     */
    private void notifyProcessEvent(ByteBuffer buffer, int type) {
        long pid = Utils.unpack_dd(buffer);
        long tid = Utils.unpack_dd(buffer);
        long pc = Utils.unpack_dq(buffer);
        long b2 = Utils.unpack_dd(buffer);
        String executable = Utils.readCString(buffer);
        long base = Utils.unpack_dq(buffer);
        long size = Utils.unpack_dq(buffer);
        long test = Utils.unpack_dq(buffer);
        if (log.isDebugEnabled()) {
            log.debug("notifyProcessEvent type=0x" + Integer.toHexString(type) + ", pid=" + pid + ", tid=" + tid + ", pc=0x" + Long.toHexString(pc) +
                    ", b2=" + b2 + ", executable=" + executable + ", base=0x" + Long.toHexString(base) + ", size=0x" + Long.toHexString(size) +
                    ", test=0x" + Long.toHexString(test));
        }

        if (type == 0x400) {
            resumeRun();
        }
    }

    private void notifyLoadModule(ByteBuffer buffer) {
        long pid = Utils.unpack_dd(buffer);
        long tid = Utils.unpack_dd(buffer);
        long address = Utils.unpack_dq(buffer);
        long s1 = Utils.unpack_dd(buffer);
        String path = Utils.readCString(buffer);
        long base = Utils.unpack_dq(buffer);
        long size = Utils.unpack_dq(buffer);
        long l1 = Utils.unpack_dq(buffer);
        if (log.isDebugEnabled()) {
            log.debug("notifyLoadModule pid=" + pid + ", tid=" + tid +
                    ", address=0x" + Long.toHexString(address) + ", s1=" + s1 + ", path=" + path +
                    ", base=0x" + Long.toHexString(base) + ", size=0x" + Long.toHexString(size) +
                    ", l1=0x" + Long.toHexString(l1));
        }
    }

    private void requestAttach(ByteBuffer buffer) {
        long pid = Utils.unpack_dd(buffer);
        int value = (int) Utils.unpack_dd(buffer);
        long b = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("requestAttach pid=" + pid + ", value=" + value + ", b=" + b);
        }

        List<Module> modules = new ArrayList<>(emulator.getMemory().getLoadedModules());
        Collections.reverse(modules);
        for (Module module : modules) {
            eventQueue.offer(new LoadModuleEvent(module));
        }

        ByteBuffer newBuf = ByteBuffer.allocate(16);
        newBuf.put((byte) 0x1);
        newBuf.put((byte) emulator.getPointerSize());
        Utils.writeCString(newBuf, "linux");
        sendAck(Utils.flipBuffer(newBuf));

        eventQueue.add(new LoadExecutableEvent());
        eventQueue.add(new AttachExecutableEvent());
    }

    private void requestRunningProcesses() {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.put((byte) 0x1);
        buffer.put((byte) 0x1); // process count
        buffer.put(Utils.pack_dd(emulator.getPid()));
        Utils.writeCString(buffer, "[" + emulator.getPointerSize() * 8 + "] " + DEBUG_EXEC_NAME);
        sendAck(Utils.flipBuffer(buffer));
    }

    @Override
    protected void onHitBreakPoint(Emulator<?> emulator, long address) {
        if (log.isDebugEnabled()) {
            log.debug("onHitBreakPoint address=0x" + Long.toHexString(address));
        }

        if (isDebuggerConnected()) {
            ByteBuffer buffer = ByteBuffer.allocate(0x20);
            buffer.put(Utils.pack_dd(0x10));
            buffer.put(Utils.pack_dd(emulator.getPid()));
            buffer.put(Utils.pack_dd(emulator.getPid()));
            buffer.put(Utils.pack_dq(address + 1));
            buffer.put(Utils.pack_dq(0x0));
            if (emulator.is32Bit()) {
                buffer.put(Utils.pack_dd(0x1));
                buffer.put(Utils.pack_dd(0x0));
                buffer.put(Utils.pack_dd(0x1));
            } else {
                buffer.put(Utils.pack_dd(0x0));
                buffer.put(Utils.pack_dd(0x0));
                buffer.put(Utils.pack_dd(0x0));
            }
            sendPacket(0x4, Utils.flipBuffer(buffer));
        }
    }

    @Override
    protected boolean onDebuggerExit() {
        if (log.isDebugEnabled()) {
            log.debug("onDebuggerExit");
        }
        sendProcessWillTerminated(0);
        return false;
    }

    @Override
    protected void onDebuggerConnected() {
        sendPacket(0x3, new byte[] {
                protocolVersion,
                IDA_DEBUGGER_ID,
                (byte) emulator.getPointerSize()
        });
    }

    @Override
    public String toString() {
        return "IDA android";
    }
}
