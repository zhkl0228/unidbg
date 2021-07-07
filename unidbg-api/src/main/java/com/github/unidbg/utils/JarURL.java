package com.github.unidbg.utils;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

class JarURL {

    static JarURL create(URL url) {
        String path = url.getPath();
        int index = path.indexOf("!");
        if (index == -1) {
            throw new IllegalStateException(path);
        }
        String jarPath = path.substring(5, index);
        String name = path.substring(index + 2);
        File jar;
        try {
            jar = new File(URLDecoder.decode(jarPath, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("jarPath=" + jarPath);
        }

        while ((index = name.indexOf("!")) != -1) {
            String jarEntryName = name.substring(0, index);
            name = name.substring(index + 2);

            JarEntry foundEntry = null;
            try (JarFile jarFile = new JarFile(jar)) {
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry jarEntry = entries.nextElement();
                    String entryName = jarEntry.getName();
                    if (jarEntryName.equals(entryName)) {
                        foundEntry = jarEntry;
                        break;
                    }
                }
                if (foundEntry == null || foundEntry.isDirectory()) {
                    throw new IllegalStateException("find failed: jar=" + jar + ", jarEntryName=" + jarEntryName + ", name=" + name + ", foundEntry=" + foundEntry);
                }

                jar = File.createTempFile(FilenameUtils.getName(jarEntryName), "");
                jar.deleteOnExit();
                try (InputStream inputStream = jarFile.getInputStream(foundEntry);
                     OutputStream outputStream = new FileOutputStream(jar)) {
                    IOUtils.copy(inputStream, outputStream);
                }
            } catch (IOException e) {
                throw new IllegalStateException(url.toString(), e);
            }
        }

        return new JarURL(jar, name);
    }

    final File jar;
    final String name;

    private JarURL(File jar, String name) {
        this.jar = jar;
        this.name = name;
    }

    final JarEntry getJarEntry() {
        JarEntry foundEntry = null;
        try (JarFile jarFile = new JarFile(jar)) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry jarEntry = entries.nextElement();
                String entryName = jarEntry.getName();
                if (name.equals(entryName) || (name + "/").equals(entryName)) {
                    foundEntry = jarEntry;
                    break;
                }
            }
            if (foundEntry == null) {
                throw new IllegalStateException("find failed: jar=" + jar + ", name=" + name);
            }
            return foundEntry;
        } catch (IOException e) {
            throw new IllegalStateException("jar=" + jar, e);
        }
    }
}
