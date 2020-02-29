package com.github.unidbg.debugger.ida;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.debugger.AbstractDebugServer;
import com.github.unidbg.debugger.ida.event.AttachEvent;
import com.github.unidbg.debugger.ida.event.DetachEvent;
import com.github.unidbg.debugger.ida.event.LoadModuleEvent;
import com.github.unidbg.debugger.ida.event.TryAttachEvent;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;
import unicorn.UnicornException;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

@Deprecated
public class AndroidServer extends AbstractDebugServer implements ModuleListener {

    private static final Log log = LogFactory.getLog(AndroidServer.class);

    private final byte protocolVersion;

    public AndroidServer(Emulator<?> emulator, byte protocolVersion) {
        super(emulator);
        this.protocolVersion = protocolVersion;
        emulator.getMemory().addModuleListener(this);
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

        if (type == 0x0 && data.length == 0) {
            return; // ack
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);
        switch (type) {
            case 0x0:
                notifyDebugEvent();
                break;
            case 0xa: {
                long value = Utils.unpack_dd(buffer);
                long b = Utils.unpack_dd(buffer);
                if (log.isDebugEnabled()) {
                    log.debug("processCommand value=0x" + Long.toHexString(value) + ", b=" + b);
                }
                sendPacket(0x0, new byte[]{0x5});
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
            case 0x13:
                requestSymbols(buffer);
                break;
            case 0x14:
                ackDebuggerEvent(buffer);
                break;
            case 0x18:
                requestMemoryRegions(buffer);
                break;
            case 0x19:
                requestReadMemory(buffer);
                break;
            case 0x1b:
                requestAddBreakPoint(buffer);
                break;
            case 0x1f:
                requestReadRegisters(buffer);
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

    private void notifyDebuggerDetached() {
        if (log.isDebugEnabled()) {
            log.debug("notifyDebuggerDetached");
        }

        sendAck();
        shutdownServer();
        resumeRun();
    }

    private void sendAck() {
        sendPacket(0x0, new byte[0]);
    }

    private void requestAddBreakPoint(ByteBuffer buffer) {
        if (log.isDebugEnabled()) {
            log.debug("requestAddBreakPoint buffer=" + buffer);
        }
    }

    private void requestTerminateProcess() {
        if (log.isDebugEnabled()) {
            log.debug("requestTerminateProcess");
        }

        notifyDebugEvent();
    }

    private void requestDetach() {
        if (log.isDebugEnabled()) {
            log.debug("requestDetach");
        }

        eventQueue.add(new DetachEvent());
        notifyDebugEvent();
    }

    private void notifyDebugEvent() {
        sendPacket(0x0, new byte[]{ 0x1 });
    }

    private void requestMemoryRegions(ByteBuffer buffer) {
        if (log.isDebugEnabled()) {
            log.debug("requestMemoryRegions buffer=" + buffer);
        }

        Collection<Module> modules = emulator.getMemory().getLoadedModules();
        List<MemRegion> list = new ArrayList<>(modules.size());
        for (Module module : modules) {
            list.addAll(module.getRegions());
        }
        Collections.sort(list);

        ByteBuffer newBuf = ByteBuffer.allocate(0x100 * list.size());
        newBuf.put(Utils.pack_dd(0x5));
        newBuf.put(Utils.pack_dd(list.size()));
        for (MemRegion region : list) {
            newBuf.putShort((short) 0x100);
            newBuf.put(Utils.pack_dd(region.begin + 1));
            newBuf.put((byte) 0);
            long size = region.end - region.begin;
            newBuf.put(Utils.pack_dd(size + 1));
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
            newBuf.putShort((short) mask);
            byte[] data = region.getName().getBytes();
            newBuf.put(Arrays.copyOf(data, data.length + 1));
            newBuf.put((byte) 0);
        }
        newBuf.flip();
        byte[] data = new byte[newBuf.remaining()];
        newBuf.get(data);
        sendPacket(0x0, data);
    }

    private void requestReadRegisters(ByteBuffer buffer) {
        long reg = Utils.unpack_dd(buffer);
        long b = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("requestReadRegisters reg=0x" + Long.toHexString(reg) + ", b=" + b);
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
                    context.getIntArg(ArmConst.UC_ARM_REG_FP),
                    context.getIntArg(ArmConst.UC_ARM_REG_IP),
                    context.getIntArg(ArmConst.UC_ARM_REG_SP),
                    context.getIntArg(ArmConst.UC_ARM_REG_LR),
                    context.getIntArg(ArmConst.UC_ARM_REG_PC),
                    context.getIntArg(ArmConst.UC_ARM_REG_CPSR))) {
                newBuf.put(Utils.pack_dd(0x1));
                newBuf.put(Utils.pack_dd(value + 1));
                newBuf.put(Utils.pack_dd(0x0));
            }

            newBuf.flip();
            byte[] data = new byte[newBuf.remaining()];
            newBuf.get(data);
            sendPacket(0x0, data);
        } else {
            throw new UnsupportedOperationException();
        }
    }

    private void requestSymbols(ByteBuffer buffer) {
        if (log.isDebugEnabled()) {
            log.debug("requestSymbols buffer=" + buffer);
        }
        sendAck();
    }

    private void requestReadMemory(ByteBuffer buffer) {
        long address = Utils.unpack_dd(buffer);
        long b = Utils.unpack_dd(buffer);
        long size = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("requestReadMemory address=0x" + Long.toHexString(address) + ", b=" + b + ", size=" + size);
        }
        try {
            Unicorn u = emulator.getUnicorn();
            byte[] data = u.mem_read(address & (~1), size);
            ByteBuffer newBuf = ByteBuffer.allocate(data.length + 0x10);
            newBuf.put(Utils.pack_dd(size));
            newBuf.put(data);

            newBuf.flip();
            data = new byte[newBuf.remaining()];
            newBuf.get(data);
            sendPacket(0x0, data);
        } catch (UnicornException e) {
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

    private Queue<DebuggerEvent> eventQueue = new LinkedBlockingQueue<>();
    private DebuggerEvent lastEvent;

    private void syncDebuggerEvent(ByteBuffer buffer) {
        long b = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("syncDebuggerEvent b=" + b);
        }

        lastEvent = eventQueue.poll();
        if (lastEvent == null) {
            sendAck();
        } else {
            byte[] packet = lastEvent.pack(emulator);
            sendPacket(0x0, packet);
        }
    }

    private void ackDebuggerEvent(ByteBuffer buffer) {
        if (lastEvent != null) {
            lastEvent.onAck(buffer);
        }
        notifyDebugEvent();
    }

    private void requestAttach(ByteBuffer buffer) {
        long pid = Utils.unpack_dd(buffer);
        int value = (int) Utils.unpack_dd(buffer);
        long b = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("requestAttach pid=" + pid + ", value=" + value + ", b=" + b);
        }

        for (Module module : emulator.getMemory().getLoadedModules()) {
            eventQueue.offer(new LoadModuleEvent(module));
        }

        ByteBuffer newBuf = ByteBuffer.allocate(16);
        newBuf.put((byte) 0x1);
        newBuf.put((byte) 0x4);
        newBuf.put("linux".getBytes());
        newBuf.put((byte) 0);
        newBuf.flip();
        byte[] packet = new byte[newBuf.remaining()];
        newBuf.get(packet);
        sendPacket(0x0, packet);

        eventQueue.add(new TryAttachEvent());
        eventQueue.add(new AttachEvent());
    }

    private void requestRunningProcesses() {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.put((byte) 0x1);
        buffer.put((byte) 0x1); // process count
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(("[" + (emulator.is32Bit() ? "32" : "64") + "] unidbg").getBytes());
        buffer.put((byte) 0);
        buffer.flip();
        byte[] packet = new byte[buffer.remaining()];
        buffer.get(packet);
        sendPacket(0x0, packet);
    }

    @Override
    protected void onHitBreakPoint(Emulator<?> emulator, long address) {
    }

    @Override
    protected void onDebuggerExit() {
    }

    private void sendPacket(int type, byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocate(data.length + 5);
        buffer.putInt(data.length);
        buffer.put((byte) type);
        buffer.put(data);
        sendData(buffer.array());
    }

    @Override
    protected void onDebuggerConnected() {
        sendPacket(0x3, new byte[] {
                protocolVersion,
                IDA_DEBUGGER_ID,
                (byte) emulator.getPointerSize()
        });
    }

}
