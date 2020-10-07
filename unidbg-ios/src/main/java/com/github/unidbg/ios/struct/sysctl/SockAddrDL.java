package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * sockaddr_dl
 */
public class SockAddrDL extends UnidbgStructure {

    public SockAddrDL(Pointer p) {
        super(p);
    }

    public byte sdl_len;	/* Total length of sockaddr */
    public byte sdl_family;	/* AF_LINK */
    public short sdl_index;	/* if != 0, system given index for interface */
    public byte sdl_type;	/* interface type */
    public byte sdl_nlen;	/* interface name length, no trailing 0 reqd. */
    public byte sdl_alen;	/* link level address length */
    public byte sdl_slen;	/* link layer selector length */
    public byte[] sdl_data = new byte[12];	/* minimum work area, can be larger; contains both if name and ll address */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sdl_len", "sdl_family", "sdl_index", "sdl_type", "sdl_nlen", "sdl_alen", "sdl_slen", "sdl_data");
    }

}
