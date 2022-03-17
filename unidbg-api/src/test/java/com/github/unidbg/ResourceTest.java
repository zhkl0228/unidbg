package com.github.unidbg;

import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import keystone.Keystone;
import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

public class ResourceTest extends TestCase {

    public void testResource() throws Exception {
        URL sub = ResourceTest.class.getResource("/sub");
        URL res = ResourceTest.class.getResource("/sub/res");
        assertNotNull(sub);
        assertNotNull(res);

        try (InputStream stream = res.openStream()) {
            assertNotNull(stream);
            String content = IOUtils.toString(stream, StandardCharsets.UTF_8);
            Inspector.inspect(content.getBytes(StandardCharsets.UTF_8), "res content");
        }
        try (InputStream stream = sub.openStream()) {
            assertNotNull(stream);
            String content = IOUtils.toString(stream, StandardCharsets.UTF_8);
            Inspector.inspect(content.getBytes(StandardCharsets.UTF_8), "sub content");
        }

        URLConnection connection = res.openConnection();
        assertNotNull(connection);
        connection.connect();

        connection = sub.openConnection();
        assertNotNull(connection);
        connection.connect();

        URL dylib = Keystone.class.getResource("/darwin/libkeystone.dylib");
        assertNotNull(dylib);
        connection = dylib.openConnection();
        assertNotNull(connection);
        connection.connect();

        URL darwin = Keystone.class.getResource("/darwin");
        assertNotNull(darwin);
        connection = darwin.openConnection();
        assertNotNull(connection);
        connection.connect();
        assertTrue(true);
    }

}
