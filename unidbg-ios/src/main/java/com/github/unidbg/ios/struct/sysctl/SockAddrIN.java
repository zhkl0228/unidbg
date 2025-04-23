package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * sockaddr_in
 */
public class SockAddrIN extends UnidbgStructure {

    public SockAddrIN(Pointer p) {
        super(p);
    }

    public byte sin_len;         /* total length */
    public byte sin_family;      /* [XSI] address family */
    public short sin_port;
    public byte[] sin_addr = new byte[4];
    public byte[] sin_zero = new byte[8];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sin_len", "sin_family", "sin_port", "sin_addr", "sin_zero");
    }

}
