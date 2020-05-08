package com.github.unidbg.ios.ipa;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSString;
import com.dd.plist.PropertyListFormatException;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.DarwinARM64Emulator;
import com.github.unidbg.ios.DarwinARMEmulator;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("unused")
public abstract class IpaLoader {

    private static final Log log = LogFactory.getLog(IpaLoader.class);

    public abstract void callEntry();

    public abstract Module getExecutable();

    public abstract Emulator<DarwinFileIO> getEmulator();

    private static String getProcessName(File ipa) throws IOException {
        String appDir = parseApp(ipa);
        UUID uuid = UUID.nameUUIDFromBytes(DigestUtils.md5(appDir));

        try {
            byte[] data = loadZip(ipa, appDir + "Info.plist");
            if (data == null) {
                throw new IllegalStateException("Find Info.plist failed");
            }
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            NSString bundleExecutable = (NSString) info.get("CFBundleExecutable");
            String executable = bundleExecutable.getContent();

            return appDir.replace("Payload", "/var/containers/Bundle/Application/" + uuid.toString().toUpperCase()) + executable;
        } catch (PropertyListFormatException | ParseException | ParserConfigurationException | SAXException e) {
            throw new IllegalStateException("load ipa failed", e);
        }
    }

    private static void config(Emulator<DarwinFileIO> emulator, File ipa, String processName) {
        File executable = new File(processName);
        SyscallHandler<DarwinFileIO> syscallHandler = emulator.getSyscallHandler();
        syscallHandler.setVerbose(log.isDebugEnabled());
        syscallHandler.addIOResolver(new IpaResolver(executable.getParentFile().getAbsolutePath(), ipa));
    }

    public static IpaLoader load32(File ipa, File rootDir, String... loads) throws IOException {
        String processName = getProcessName(ipa);
        Emulator<DarwinFileIO> emulator = new DarwinARMEmulator(processName, rootDir);
        config(emulator, ipa, processName);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        return load(emulator, ipa, false, loads);
    }

    public static IpaLoader load64(File ipa, File rootDir, String... loads) throws IOException {
        String processName = getProcessName(ipa);
        Emulator<DarwinFileIO> emulator = new DarwinARM64Emulator(processName, rootDir);
        config(emulator, ipa, processName);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        return load(emulator, ipa, false, loads);
    }

    public static IpaLoader load(Emulator<DarwinFileIO> emulator, File ipa, String... loads) throws IOException {
        return load(emulator, ipa, false, loads);
    }

    public static IpaLoader load(Emulator<DarwinFileIO> emulator, File ipa, boolean forceCallInit, String... loads) throws IOException {
        try {
            String appDir = parseApp(ipa);
            byte[] data = loadZip(ipa, appDir + "Info.plist");
            if (data == null) {
                throw new IllegalStateException("Find Info.plist failed");
            }
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            NSString bundleExecutable = (NSString) info.get("CFBundleExecutable");
            String executable = bundleExecutable.getContent();
            Memory memory = emulator.getMemory();
            Module module = memory.load(new IpaLibraryFile(appDir, ipa, executable, loads), forceCallInit);
            MachOLoader loader = (MachOLoader) memory;
            loader.onExecutableLoaded();
            return new IpaLoaderImpl(emulator, module);
        }  catch (PropertyListFormatException | ParseException | ParserConfigurationException | SAXException e) {
            throw new IllegalStateException("load ipa failed", e);
        }
    }

    private static final Pattern PATTERN = Pattern.compile("^(Payload/\\w+\\.app/)");

    private static String parseApp(File ipa) throws IOException {
        try (JarFile file = new JarFile(ipa)) {
            Enumeration<JarEntry> enumeration = file.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (!entry.getName().startsWith("Payload/")) {
                    continue;
                }
                Matcher matcher = PATTERN.matcher(entry.getName());
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }
        }
        throw new IllegalStateException("NOT app ipa");
    }

    static byte[] loadZip(File file, String path) throws IOException {
        try (JarFile jarFile = new JarFile(file)) {
            JarEntry entry = jarFile.getJarEntry(path);
            if (entry != null) {
                try (InputStream inputStream = jarFile.getInputStream(entry)) {
                    return IOUtils.toByteArray(inputStream);
                }
            }
        }
        return null;
    }

}
