package com.github.unidbg.ios.ipa;

import com.dd.plist.*;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.memory.Memory;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public abstract class IpaLoader {

    public abstract void callEntry();

    public abstract Module getExecutable();

    public static IpaLoader load(Emulator emulator, File ipa, boolean forceCallInit, String... loads) throws IOException {
        try {
            String appDir = parseMetadata(ipa);
            byte[] data = loadZip(ipa, appDir + "Info.plist");
            if (data == null) {
                throw new IllegalStateException("Find Info.plist failed");
            }
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            NSString bundleExecutable = (NSString) info.get("CFBundleExecutable");
            String executable = bundleExecutable.getContent();
            Memory memory = emulator.getMemory();
            Module module = memory.load(new IpaLibraryFile(appDir, ipa, executable, loads), forceCallInit);
            return new IpaLoaderImpl(emulator, module);
        }  catch (PropertyListFormatException | ParseException | ParserConfigurationException | SAXException e) {
            throw new IllegalStateException("load ipa failed", e);
        }
    }

    private static String parseMetadata(File ipa) throws IOException, ParserConfigurationException, ParseException, SAXException, PropertyListFormatException {
        byte[] data = loadZip(ipa, "iTunesMetadata.plist");
        if (data == null) {
            throw new IllegalStateException("iTunesMetadata.plist not exists");
        }
        String xml = new String(data, StandardCharsets.UTF_8).trim();
        NSDictionary metadata = (NSDictionary) XMLPropertyListParser.parse(xml.getBytes(StandardCharsets.UTF_8));
        NSString bundleDisplayName = (NSString) metadata.get("bundleDisplayName");
        NSString fileExtension = (NSString) metadata.get("fileExtension");
        if (!".app".equals(fileExtension.getContent())) {
            throw new IllegalArgumentException("ipa is not app");
        }
        return "Payload/" + bundleDisplayName.getContent() + ".app/";
    }

    static byte[] loadZip(File file, String path) throws IOException {
        String absolutePath = FilenameUtils.normalize(path);
        try (JarFile jarFile = new JarFile(file)) {
            Enumeration<JarEntry> enumeration = jarFile.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (absolutePath.equals(entry.getName())) {
                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
                        return IOUtils.toByteArray(inputStream);
                    }
                }
            }
        }
        return null;
    }

}
