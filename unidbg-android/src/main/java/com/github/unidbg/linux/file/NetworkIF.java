package com.github.unidbg.linux.file;

import java.net.Inet4Address;

public class NetworkIF {

    public final int index;
    public final String ifName;
    public final Inet4Address ipv4;
    public final Inet4Address broadcast;

    public NetworkIF(int index, String ifName, Inet4Address ipv4) {
        this(index, ifName, ipv4, null);
    }

    public NetworkIF(int index, String ifName, Inet4Address ipv4, Inet4Address broadcast) {
        this.index = index;
        this.ifName = getIfName(ifName);
        this.ipv4 = ipv4;
        this.broadcast = broadcast;
    }

    private String getIfName(String ifName) {
        if ("lo0".equals(ifName)) {
            return "lo";
        }
        if ("en0".equals(ifName)) {
            return "wlan0";
        }
        return ifName;
    }

    public boolean isLoopback() {
        return ifName.startsWith("lo");
    }

    @Override
    public String toString() {
        return ifName;
    }
}
