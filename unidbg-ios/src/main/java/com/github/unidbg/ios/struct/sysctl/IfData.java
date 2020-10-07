package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.unix.struct.TimeVal32;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public final class IfData extends UnidbgStructure {

    public IfData(Pointer p) {
        super(p);
    }

    /* generic interface information */
    public byte     ifi_type;	/* ethernet, tokenring, etc */
    public byte     ifi_typelen;	/* Length of frame type id */
    public byte     ifi_physical;	/* e.g., AUI, Thinnet, 10base-T, etc */
    public byte     ifi_addrlen;	/* media address length */
    public byte     ifi_hdrlen;	/* media header length */
    public byte     ifi_recvquota;	/* polling quota for receive intrs */
    public byte     ifi_xmitquota;	/* polling quota for xmit intrs */
    public byte     ifi_unused1;	/* for future use */
    public int      ifi_mtu;	/* maximum transmission unit */
    public int      ifi_metric;	/* routing metric (external only) */
    public int      ifi_baudrate;	/* linespeed */

    /* volatile statistics */
    public int      ifi_ipackets;	/* packets received on interface */
    public int      ifi_ierrors;	/* input errors on interface */
    public int      ifi_opackets;	/* packets sent on interface */
    public int      ifi_oerrors;	/* output errors on interface */
    public int      ifi_collisions;	/* collisions on csma interfaces */
    public int      ifi_ibytes;	/* total number of octets received */
    public int      ifi_obytes;	/* total number of octets sent */
    public int      ifi_imcasts;	/* packets received via multicast */
    public int      ifi_omcasts;	/* packets sent via multicast */
    public int      ifi_iqdrops;	/* dropped on input, this interface */
    public int      ifi_noproto;	/* destined for unsupported protocol */
    public int      ifi_recvtiming;	/* usec spent receiving when timing */
    public int      ifi_xmittiming;	/* usec spent xmitting when timing */
    public TimeVal32 ifi_lastchange;	/* time of last administrative change */
    public int      ifi_unused2;	/* used to be the default_proto */
    public int      ifi_hwassist;	/* HW offload capabilities */
    public int      ifi_reserved1;	/* for future use */
    public int      ifi_reserved2;	/* for future use */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ifi_type", "ifi_typelen", "ifi_physical", "ifi_addrlen", "ifi_hdrlen",
                "ifi_recvquota", "ifi_xmitquota", "ifi_unused1", "ifi_mtu", "ifi_metric", "ifi_baudrate",
                "ifi_ipackets", "ifi_ierrors", "ifi_opackets", "ifi_oerrors", "ifi_collisions",
                "ifi_ibytes", "ifi_obytes", "ifi_imcasts", "ifi_omcasts", "ifi_iqdrops", "ifi_noproto",
                "ifi_recvtiming", "ifi_xmittiming", "ifi_lastchange",
                "ifi_unused2", "ifi_hwassist", "ifi_reserved1", "ifi_reserved2");
    }

}
