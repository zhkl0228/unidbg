package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;
import com.sun.jna.Pointer;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public class PipedSocketIO extends TcpSocket implements FileIO {

    private final PipedInputStream pipedInputStream = new PipedInputStream();

    public PipedSocketIO(Emulator<?> emulator) {
        super(emulator);
        this.inputStream = new BufferedInputStream(pipedInputStream);
        this.outputStream = new PipedOutputStream();
    }

    public void connectPeer(PipedSocketIO io) {
        try {
            ((PipedOutputStream) this.outputStream).connect(io.pipedInputStream);
            ((PipedOutputStream) io.outputStream).connect(this.pipedInputStream);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int sendto(byte[] data, int flags, Pointer dest_addr, int addrlen) {
        flags &= ~MSG_NOSIGNAL;
        final int MSG_EOR = 0x80;
        if (flags == MSG_EOR && dest_addr == null && addrlen == 0) {
            return write(data);
        }

        return super.sendto(data, flags, dest_addr, addrlen);
    }

}
