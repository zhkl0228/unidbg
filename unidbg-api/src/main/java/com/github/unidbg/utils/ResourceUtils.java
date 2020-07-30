package com.github.unidbg.utils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ResourceUtils {

    public static File extractResource(Class<?> clazz, String resource, String path) {
        URL url = clazz.getResource(resource);
        if (url != null) {
            if (isFile(url)) {
                OutputStream outputStream = null;
                try (InputStream inputStream = url.openStream()) {
                    File file = new File(new File(FileUtils.getTempDirectory(), "unidbg"), path);
                    File dir = file.getParentFile();
                    if (dir.exists() && dir.isFile()) {
                        FileUtils.deleteQuietly(dir);
                    }
                    FileUtils.forceMkdir(dir);

                    outputStream = new FileOutputStream(file);
                    IOUtils.copy(inputStream, outputStream);
                    return file;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                } finally {
                    IOUtils.closeQuietly(outputStream);
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
            JarEntry foundEntry = findJarEntry(url);
            String foundName = foundEntry.getName();

            String path = url.getPath();
            int index = path.indexOf("!");
            if (index == -1) {
                throw new IllegalStateException(path);
            }
            String jarPath = path.substring(5, index);
            try (JarFile jarFile = new JarFile(URLDecoder.decode(jarPath, "UTF-8"))) {
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
                            OutputStream outputStream = null;
                            try (InputStream inputStream = jarFile.getInputStream(jarEntry)) {
                                File out = new File(dir, sub);
                                outputStream = new FileOutputStream(out);
                                IOUtils.copy(inputStream, outputStream);
                            } finally {
                                IOUtils.closeQuietly(outputStream);
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
            JarEntry foundEntry = findJarEntry(url);
            return !foundEntry.isDirectory();
        }
        throw new UnsupportedOperationException("protocol=" + protocol + ", url=" + url);
    }

    private static JarEntry findJarEntry(URL url) {
        String path = url.getPath();
        int index = path.indexOf("!");
        if (index == -1) {
            throw new IllegalStateException(path);
        }
        String jarPath = path.substring(5, index);
        String name = path.substring(index + 2);
        JarEntry foundEntry = null;
        try (JarFile jarFile = new JarFile(URLDecoder.decode(jarPath, "UTF-8"))) {
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
                throw new IllegalStateException("find failed: jarPath=" + jarPath + ", name=" + name);
            }
            return foundEntry;
        } catch (IOException e) {
            throw new IllegalStateException(url.toString(), e);
        }
    }

}
