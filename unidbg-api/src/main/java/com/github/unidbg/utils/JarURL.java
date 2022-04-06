package com.github.unidbg.utils;

import org.apache.commons.io.FileUtils;
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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

class JarURL implements AutoCloseable {

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

        List<File> cleanupList = new ArrayList<>();
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
                try (InputStream inputStream = jarFile.getInputStream(foundEntry);
                     OutputStream outputStream = new FileOutputStream(jar)) {
                    IOUtils.copy(inputStream, outputStream);
                }
                cleanupList.add(jar);
            } catch (IOException e) {
                throw new IllegalStateException(url.toString(), e);
            }
        }

        return new JarURL(jar, name, cleanupList);
    }

    final File jar;
    final String name;
    private final List<File> cleanupList;

    private JarURL(File jar, String name, List<File> cleanupList) {
        this.jar = jar;
        this.name = name;
        this.cleanupList = cleanupList;
    }

    @Override
    public void close() {
        for (File file : cleanupList) {
            FileUtils.deleteQuietly(file);
        }
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
