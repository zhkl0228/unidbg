package com.github.unidbg.ios;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class DarwinUtils {

    private static final Log log = LogFactory.getLog(DarwinUtils.class);

    static class NetworkIF {
        final NetworkInterface networkInterface;
        public NetworkIF(NetworkInterface networkInterface) {
            this.networkInterface = networkInterface;
        }
        @Override
        public String toString() {
            return networkInterface.getName();
        }
    }

    static List<NetworkIF> getNetworkIFs(boolean verbose) throws SocketException {
        Enumeration<NetworkInterface> enumeration = NetworkInterface.getNetworkInterfaces();
        List<NetworkIF> list = new ArrayList<>();
        while (enumeration.hasMoreElements()) {
            NetworkInterface networkInterface = enumeration.nextElement();
            if (networkInterface.getHardwareAddress() == null) {
                continue;
            }
            Enumeration<InetAddress> addressEnumeration = networkInterface.getInetAddresses();
            if (addressEnumeration.hasMoreElements()) {
                list.add(new NetworkIF(networkInterface));
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Return host network ifs: " + list);
        }
        if (verbose) {
            System.out.println("Return host network ifs: " + list);
        }
        return list;
    }

}
