package cn.banny.unidbg.debugger.ida;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.debugger.AbstractDebugServer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;

public class AndroidServer extends AbstractDebugServer {

    private static final Log log = LogFactory.getLog(AndroidServer.class);

    private final byte protocolVersion;

    public AndroidServer(Emulator emulator, byte protocolVersion) {
        super(emulator);
        this.protocolVersion = protocolVersion;
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

        switch (type) {
            case 0x0:
            case 0x14:
                sendPacket(0x0, new byte[] { 0x1 });
                break;
            case 0xa:
                sendPacket(0x0, new byte[] { 0x5 });
                break;
            case 0xc: {
                requestRunningProcesses();
                break;
            }
            case 0xf:
                requestAttach();
                break;
            case 0x11:
                requestElement();
                break;
            case 0x22:
                sendPacket(0x0, new byte[0]);
                break;
            default:
                log.warn(Inspector.inspectString(data, "Not handler command type=0x" + Integer.toHexString(type)));
                break;
        }
    }

    private void requestElement() {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.put((byte) 0x2); // thread
        buffer.put((byte) 0x4);
        buffer.putInt(0x84e584f9);
        buffer.put((byte) 0x0);
        buffer.put((byte) 0x1);
        buffer.put((byte) 0x1);
        buffer.put("main".getBytes());
        buffer.put((byte) 0);
        buffer.flip();
        byte[] packet = new byte[buffer.remaining()];
        buffer.get(packet);
        sendPacket(0x0, packet);
    }

    private void requestAttach() {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.put((byte) 0x1);
        buffer.put((byte) 0x4);
        buffer.put("linux".getBytes());
        buffer.put((byte) 0);
        buffer.flip();
        byte[] packet = new byte[buffer.remaining()];
        buffer.get(packet);
        sendPacket(0x0, packet);
    }

    private void requestRunningProcesses() {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.put((byte) 0x1);
        buffer.put((byte) 0x1); // process count
        buffer.put((byte) 0x1); // id
        buffer.put(("[" + emulator.getPid() + "] unidbg").getBytes());
        buffer.put((byte) 0);
        buffer.flip();
        byte[] packet = new byte[buffer.remaining()];
        buffer.get(packet);
        sendPacket(0x0, packet);
    }

    @Override
    protected void onHitBreakPoint(Emulator emulator, long address) {
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
