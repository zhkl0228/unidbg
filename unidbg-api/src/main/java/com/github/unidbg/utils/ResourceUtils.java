package com.github.unidbg.utils;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

public class ResourceUtils {

    public static File toFile(URL url) {
        String protocol = url.getProtocol();
        if ("file".equals(protocol)) {
            try {
                return new File(url.toURI());
            } catch (URISyntaxException e) {
                throw new IllegalStateException(url.toString(), e);
            }
        }
        return null;
    }

}
