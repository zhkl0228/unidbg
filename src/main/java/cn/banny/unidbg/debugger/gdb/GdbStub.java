package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.arm.AbstractARMDebugger;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.concurrent.Semaphore;

/**
 * GdbStub class
 * @author Humberto Silva Naves
 */
public final class GdbStub extends AbstractARMDebugger implements Runnable {

    private static final Log log = LogFactory.getLog(GdbStub.class);

    private static final int DEFAULT_PORT = 2159;
    static final String SIGTRAP = "05"; /* Trace trap (POSIX).  */

    final int[] registers;

    private String lastPacket;
    private StringBuilder currentInputPacket;
    private int packetChecksum, packetFinished;
    private boolean closeConnection, serverShutdown, serverRunning;

    private Selector selector;
    private ServerSocketChannel serverSocketChannel;
    private SocketChannel socketChannel;
    private ByteBuffer input;
    private List<ByteBuffer> pendingWrites;

    public GdbStub(Emulator emulator) {
        super(emulator, true);

        if (emulator.getPointerSize() == 4) { // arm32
            registers = new int[] {
                    ArmConst.UC_ARM_REG_R0,
                    ArmConst.UC_ARM_REG_R1,
                    ArmConst.UC_ARM_REG_R2,
                    ArmConst.UC_ARM_REG_R3,
                    ArmConst.UC_ARM_REG_R4,
                    ArmConst.UC_ARM_REG_R5,
                    ArmConst.UC_ARM_REG_R6,
                    ArmConst.UC_ARM_REG_R7,
                    ArmConst.UC_ARM_REG_R8,
                    ArmConst.UC_ARM_REG_R9,
                    ArmConst.UC_ARM_REG_R10,
                    ArmConst.UC_ARM_REG_R11,
                    ArmConst.UC_ARM_REG_R12,
                    ArmConst.UC_ARM_REG_SP,
                    ArmConst.UC_ARM_REG_LR,
                    ArmConst.UC_ARM_REG_PC,
                    ArmConst.UC_ARM_REG_CPSR
            };
        } else { // arm64
            registers = new int[34];
            for (int i = 0; i <= 28; i++) {
                registers[i] = Arm64Const.UC_ARM64_REG_X0 + i;
            }
            registers[29] = Arm64Const.UC_ARM64_REG_X29;
            registers[30] = Arm64Const.UC_ARM64_REG_X30;
            registers[31] = Arm64Const.UC_ARM64_REG_SP;
            registers[32] = Arm64Const.UC_ARM64_REG_PC;
            registers[33] = Arm64Const.UC_ARM64_REG_NZCV;
        }

        Thread thread = new Thread(this, "gdbserver");
        thread.start();
    }

    @Override
    public void close() {
        super.close();

        makePacketAndSend("W00");
        shutdownServer();
    }

    @Override
    public void run() {
        runServer();
    }

    private Semaphore semaphore;

    @Override
    protected void loop(Emulator emulator, Unicorn u, long address, int size) throws Exception {
        semaphore = new Semaphore(0);

        if (socketChannel != null) {
            makePacketAndSend("S" + SIGTRAP);
        }
        semaphore.acquire();
    }

    final void resumeRun() {
        semaphore.release();
    }

    private void runServer() {
        selector = null;
        serverSocketChannel = null;
        socketChannel = null;
        try {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.configureBlocking(false);

            serverSocketChannel.socket().bind(new InetSocketAddress(GdbStub.DEFAULT_PORT));

            selector = Selector.open();
            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
        } catch(IOException ex) {
            throw new IllegalStateException(ex);
        }

        pendingWrites = new LinkedList<>();
        currentInputPacket = new StringBuilder();
        input = ByteBuffer.allocate(1024);
        serverShutdown = false;
        serverRunning = true;

        System.err.println("Start gdbserver successfully");

        while(serverRunning) {
            try {
                selector.select(50);
                Iterator<SelectionKey> selectedKeys = selector.selectedKeys().iterator();
                while (selectedKeys.hasNext()) {
                    SelectionKey key = selectedKeys.next();
                    if (key.isValid()) {
                        if (key.isAcceptable()) {
                            onSelectAccept(key);
                        }
                        if (key.isReadable()) {
                            onSelectRead(key);
                        }
                        if (key.isWritable()) {
                            onSelectWrite(key);
                        }
                    }
                    selectedKeys.remove();
                }
                processCommands();
            } catch(Throwable ignored) {
            }
        }

        IOUtils.closeQuietly(serverSocketChannel);
        serverSocketChannel = null;
        IOUtils.closeQuietly(selector);
        selector = null;
        closeSocketChannel();
    }

    private void enableNewConnections(boolean enable) {
        if (serverSocketChannel == null) return;
        SelectionKey key = serverSocketChannel.keyFor(selector);
        key.interestOps(enable ? SelectionKey.OP_ACCEPT : 0);
    }

    private void enableWrites(boolean enable) {
        if (socketChannel == null) return;
        SelectionKey key = socketChannel.keyFor(selector);
        key.interestOps(enable ? SelectionKey.OP_WRITE : SelectionKey.OP_READ);
    }

    private void closeSocketChannel() {
        if (socketChannel == null) {
            return;
        }
        SelectionKey key = socketChannel.keyFor(selector);
        if (key != null) key.cancel();
        IOUtils.closeQuietly(socketChannel);
        socketChannel = null;
        if (!serverShutdown) {
            enableNewConnections(true);
        } else {
            serverRunning = false;
        }
    }

    final void shutdownServer() {
        serverShutdown = true;
        closeConnection = true;
        enableWrites(true);
    }

    final void detachServer() {
        closeConnection = true;
        enableWrites(true);
    }

    private void onSelectAccept(SelectionKey key) throws IOException {
        ServerSocketChannel ssc = (ServerSocketChannel) key.channel();
        SocketChannel sc = ssc.accept();
        if (sc != null) {
            closeConnection = false;
            pendingWrites.clear();
            input.clear();
            sc.configureBlocking(false);
            sc.register(key.selector(), SelectionKey.OP_READ);
            socketChannel = sc;
            enableNewConnections(false);
        }
    }

    private void onSelectRead(SelectionKey key) {
        SocketChannel sc = (SocketChannel) key.channel();

        int numRead;
        try {
            numRead = sc.read(input);
        } catch(IOException ex) {
            numRead = -1;
        }

        if (numRead == -1) {
            closeSocketChannel();
        }
    }

    private void onSelectWrite(SelectionKey key) throws IOException {
        SocketChannel sc = (SocketChannel) key.channel();
        if (pendingWrites.isEmpty() && closeConnection) {
            closeSocketChannel();
            return;
        }

        while(!pendingWrites.isEmpty()) {
            ByteBuffer bb = pendingWrites.get(0);
            try {
                sc.write(bb);
            } catch(IOException ex) {
                closeSocketChannel();
                throw ex;
            }
            if (bb.remaining() > 0) {
                break;
            }
            pendingWrites.remove(0);
        }

        if (pendingWrites.isEmpty() && !closeConnection) {
            enableWrites(false);
        }
    }

    final void send(String packet) {
        ByteBuffer bb = ByteBuffer.wrap(packet.getBytes());
        pendingWrites.add(bb);
        enableWrites(true);
    }

    private void sendPacket(String packet) {
        lastPacket = packet;
        send(packet);
    }

    final void makePacketAndSend(String data) {
        if (log.isDebugEnabled()) {
            log.debug("makePacketAndSend: " + data);
        }

        int checksum = 0;
        data = escapePacketData(data);
        StringBuilder sb = new StringBuilder();
        sb.append("+");
        sb.append("$");
        for(int i = 0; i < data.length(); i++) {
            sb.append(data.charAt(i));
            checksum += (byte) data.charAt(i);
        }
        sb.append("#");
        sb.append(String.format("%02x", checksum & 0xff));
        sendPacket(sb.toString());
    }

    private String escapePacketData(String data) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            if (c == '$' || c == '#' || c == '}') {
                sb.append("}");
                sb.append(c ^ 0x20);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private void processCommands() {
        input.flip();
        while(input.hasRemaining()) {
            char c = (char) input.get();
            if (currentInputPacket.length() == 0) {
                switch (c) {
                    case '-':
                        reTransmitLastPacket();
                        break;
                    case '+': // Silently discard '+' packets
                    case 0x3: // Ctrl-C requests
                        break;
                    case '$':
                        currentInputPacket.append(c);
                        packetChecksum = 0;
                        packetFinished = 0;
                        break;
                    default:
                        requestRetransmit();
                        break;

                }
            } else {
                currentInputPacket.append(c);
                if (packetFinished > 0) {
                    if (++packetFinished == 3) {
                        if (checkPacket()) {
                            processCommand(currentInputPacket.substring(1, currentInputPacket.length() - 3));
                        } else {
                            requestRetransmit();
                        }
                        currentInputPacket.setLength(0);
                    }
                } else if (c == '#') {
                    packetFinished = 1;
                } else {
                    packetChecksum += c;
                }
            }
        }
        input.clear();
    }

    private void requestRetransmit() {
        send("-");
    }

    private void reTransmitLastPacket() {
        send(lastPacket);
    }

    private boolean checkPacket() {
        try {
            int checksum = Integer.parseInt(currentInputPacket.substring(currentInputPacket.length() - 2), 16);
            return checksum == (packetChecksum & 0xff);
        } catch(NumberFormatException ex) {
            log.debug("checkPacket currentInputPacket=" + currentInputPacket, ex);
            return false;
        }
    }

    private void processCommand(String command) {
        for(String prefix : commands.keySet()) {
            if (command.startsWith(prefix)) {
                GdbStubCommand cmd = commands.get(prefix);
                if (log.isDebugEnabled()) {
                    log.debug("processCommand command=" + command + ", cmd=" + cmd);
                }
                if (cmd.processCommand(emulator, this, command)) {
                    return;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Unsupported command=" + command);
        }
        makePacketAndSend("");
    }

    private static final Map<String, GdbStubCommand> commands;

    private static void registerCommand(String commandPrefix, GdbStubCommand command) {
        commands.put(commandPrefix, command);
    }

    static {
        commands = new HashMap<>();
        GdbStubCommand commandContinue = new ContinueCommand();
        registerCommand("c", commandContinue);

        GdbStubCommand commandStep = new StepCommand();
        registerCommand("s", commandStep);

        GdbStubCommand commandBreakpoint = new BreakpointCommand();
        registerCommand("z0", commandBreakpoint);
        registerCommand("Z0", commandBreakpoint);

        GdbStubCommand commandMemory = new MemoryCommand();
        registerCommand("m", commandMemory);
        registerCommand("M", commandMemory);

        GdbStubCommand commandRegisters = new RegistersCommand();
        registerCommand("g", commandRegisters);
        registerCommand("G", commandRegisters);

        GdbStubCommand commandRegister = new RegisterCommand();
        registerCommand("p", commandRegister);
        registerCommand("P", commandRegister);

        GdbStubCommand commandKill = new KillCommand();
        registerCommand("k", commandKill);

        GdbStubCommand commandQSupported = new QSupportedCommand();
        registerCommand("qSupported", commandQSupported);

        GdbStubCommand commandLastSignal = new LastSignalCommand();
        registerCommand("?", commandLastSignal);

        GdbStubCommand commandDetach = new DetachCommand();
        registerCommand("D", commandDetach);

        GdbStubCommand commandQuery = new QueryCommand();
        registerCommand("q", commandQuery);
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber) {
        if (emulator.getPointerSize() == 4) {
            boolean isThumb = (address & 1) != 0;
            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, isThumb ? KeystoneMode.ArmThumb : KeystoneMode.Arm)) {
                KeystoneEncoded encoded = keystone.assemble("bkpt #" + svcNumber);
                return encoded.getMachineCode();
            }
        } else {
            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                KeystoneEncoded encoded = keystone.assemble("brk #" + svcNumber);
                return encoded.getMachineCode();
            }
        }
    }
}