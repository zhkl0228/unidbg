package com.github.unidbg.utils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ResourceUtils {

    public static File extractResource(Class<?> clazz, String resource, String path) {
        URL url = clazz.getResource(resource);
        if (url != null) {
            if (isFile(url)) {
                File file = new File(new File(FileUtils.getTempDirectory(), "unidbg"), path);
                File dir = file.getParentFile();
                if (dir.exists() && dir.isFile()) {
                    FileUtils.deleteQuietly(dir);
                }
                try {
                    FileUtils.forceMkdir(dir);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }

                try (InputStream inputStream = url.openStream();
                     OutputStream outputStream = new FileOutputStream(file)) {
                    IOUtils.copy(inputStream, outputStream);
                    return file;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            } else { // is directory
                try {
                    File dir = new File(new File(FileUtils.getTempDirectory(), "unidbg"), path);
                    if (dir.exists() && dir.isFile()) {
                        FileUtils.deleteQuietly(dir);
                    }
                    FileUtils.forceMkdir(dir);
                    extractJarResource(url, dir);
                    return dir;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        return null;
    }

    private static void extractJarResource(URL url, File dir) {
        String protocol = url.getProtocol();
        if ("jar".equals(protocol)) {
            JarURL jarURL = JarURL.create(url);
            JarEntry foundEntry = jarURL.getJarEntry();
            String foundName = foundEntry.getName();

            try (JarFile jarFile = new JarFile(jarURL.jar)) {
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry jarEntry = entries.nextElement();
                    String entryName = jarEntry.getName();
                    if (entryName.equals(foundName)) {
                        continue;
                    }
                    if (entryName.startsWith(foundName)) {
                        String sub = entryName.substring(foundName.length());
                        int check = sub.indexOf('/');
                        if (check == -1 && !jarEntry.isDirectory()) { // sub file
                            File out = new File(dir, sub);
                            try (InputStream inputStream = jarFile.getInputStream(jarEntry);
                                 OutputStream outputStream = new FileOutputStream(out)) {
                                IOUtils.copy(inputStream, outputStream);
                            }
                        } else if (check != -1 && check + 1 == sub.length() && jarEntry.isDirectory()) {
                            File subDir = new File(dir, sub.substring(0, check));
                            FileUtils.forceMkdir(subDir);
                        }
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException(url.toString(), e);
            }
        }
    }

    private static boolean isFile(URL url) {
        String protocol = url.getProtocol();
        if ("file".equals(protocol)) {
            try {
                return new File(url.toURI()).isFile();
            } catch (URISyntaxException e) {
                throw new IllegalStateException(url.toString(), e);
            }
        }
        if ("jar".equals(protocol)) {
            JarURL jarURL = JarURL.create(url);
            JarEntry foundEntry = jarURL.getJarEntry();
            return !foundEntry.isDirectory();
        }
        throw new UnsupportedOperationException("protocol=" + protocol + ", url=" + url);
    }

}
