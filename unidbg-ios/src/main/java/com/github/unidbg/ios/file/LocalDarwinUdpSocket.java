package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.unix.UnixEmulator;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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
        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }

    @Override
    public int getattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getdirentries64(Pointer buf, int bufSize) {
        throw new UnsupportedOperationException();
    }
}
