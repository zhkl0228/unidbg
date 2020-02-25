package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.file.LocalUdpSocket;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.StandardCharsets;

public class LocalDarwinUdpSocket extends LocalUdpSocket {

    private static final Log log = LogFactory.getLog(LocalDarwinUdpSocket.class);

    public LocalDarwinUdpSocket(Emulator<?> emulator) {
        super(emulator);
    }

    @Override
    public int connect(Pointer addr, int addrlen) {
        String path = addr.getString(2);
        log.debug("connect path=" + path);

        return connect(path);
    }

    @Override
    protected int connect(String path) {
        if ("/var/run/syslog".equals(path)) {
            handler = new UdpHandler() {
                @Override
                public void handle(byte[] request) {
                    System.err.print("syslog: " + new String(request, StandardCharsets.UTF_8));
                }
            };
            return 0;
        }

        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }
}
