package com.github.unidbg.debugger;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.AbstractARMDebugger;
import com.github.unidbg.utils.Inspector;
import keystone.Keystone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Semaphore;

public abstract class AbstractDebugServer extends AbstractARMDebugger implements DebugServer {

    private static final Logger log = LoggerFactory.getLogger(AbstractDebugServer.class);

    private final List<ByteBuffer> pendingWrites;

    public AbstractDebugServer(Emulator<?> emulator) {
        super(emulator);

        pendingWrites = new LinkedList<>();
        input = ByteBuffer.allocate(PACKET_SIZE);

        setSingleStep(1); // break at attach

        Thread thread = new Thread(this, "dbgserver");
        thread.start();
    }

    private Selector selector;
    private ServerSocketChannel serverSocketChannel;
    private SocketChannel socketChannel;
    private final ByteBuffer input;

    private boolean serverShutdown, closeConnection;
    private boolean serverRunning;

    protected final boolean isDebuggerConnected() {
        return socketChannel != null;
    }

    @Override
    public final void run() {
        runServer();
    }

    private void runServer() {
        selector = null;
        serverSocketChannel = null;
        socketChannel = null;
        try {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.configureBlocking(false);

            serverSocketChannel.socket().bind(new InetSocketAddress(DEFAULT_PORT));

            selector = Selector.open();
            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
        } catch(IOException ex) {
            throw new IllegalStateException(ex);
        }

        serverShutdown = false;
        serverRunning = true;

        System.err.println("Start " + this + " server on port: " + DEFAULT_PORT);
        onServerStart();

        while(serverRunning) {
            try {
                int count = selector.select(50);
                if (count <= 0) {
                    if (!isDebuggerConnected() && System.in.available() > 0) {
                        String line = new Scanner(System.in).nextLine();
                        if ("c".equals(line)) {
                            serverRunning = false;
                            break;
                        } else {
                            System.out.println("c: continue");
                        }
                    }
                    continue;
                }

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

                processInput(input);
            } catch(Throwable e) {
                if (log.isDebugEnabled()) {
                    log.debug("run server ex", e);
                }
            }
        }

        com.alibaba.fastjson.util.IOUtils.close(serverSocketChannel);
        serverSocketChannel = null;
        com.alibaba.fastjson.util.IOUtils.close(selector);
        selector = null;
        closeSocketChannel();
        resumeRun();
    }

    protected abstract void onServerStart();

    protected abstract void processInput(ByteBuffer input);

    private void enableNewConnections(boolean enable) {
        if (serverSocketChannel == null) {
            return;
        }
        SelectionKey key = serverSocketChannel.keyFor(selector);
        key.interestOps(enable ? SelectionKey.OP_ACCEPT : 0);
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
            onDebuggerConnected();
        }
    }

    protected abstract void onDebuggerConnected();

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

    private void closeSocketChannel() {
        if (socketChannel == null) {
            return;
        }
        SelectionKey key = socketChannel.keyFor(selector);
        if (key != null) key.cancel();
        IOUtils.close(socketChannel);
        socketChannel = null;
        if (!serverShutdown) {
            enableNewConnections(true);
        } else {
            serverRunning = false;
        }
    }

    private void enableWrites(boolean enable) {
        if (socketChannel == null) {
            return;
        }
        SelectionKey key = socketChannel.keyFor(selector);
        key.interestOps(enable ? SelectionKey.OP_WRITE : SelectionKey.OP_READ);
    }

    protected final void sendData(byte[] data) {
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(data, "sendData"));
        }
        ByteBuffer bb = ByteBuffer.wrap(data);
        pendingWrites.add(bb);
        enableWrites(true);
    }

    private Semaphore semaphore;

    @Override
    protected final void loop(Emulator<?> emulator, long address, int size, DebugRunnable<?> runnable) throws Exception {
        if (address <= 0) {
            return;
        }

        semaphore = new Semaphore(0);

        onHitBreakPoint(emulator, address);
        semaphore.acquire();
    }

    @Override
    public <T> T run(DebugRunnable<T> runnable) {
        throw new UnsupportedOperationException();
    }

    protected abstract void onHitBreakPoint(Emulator<?> emulator, long address);

    public final void resumeRun() {
        if (semaphore != null) {
            semaphore.release();
        }
    }

    public final void singleStep() {
        setSingleStep(1);
        resumeRun();
    }

    @Override
    public final void close() {
        super.close();

        if (onDebuggerExit()) {
            shutdownServer();
        }
    }

    protected abstract boolean onDebuggerExit();

    public final void shutdownServer() {
        serverShutdown = true;
        closeConnection = true;
        enableWrites(true);
    }

    public final void detachServer() {
        closeConnection = true;
        enableWrites(true);
    }

    @Override
    protected Keystone createKeystone(boolean isThumb) {
        throw new UnsupportedOperationException();
    }
}
