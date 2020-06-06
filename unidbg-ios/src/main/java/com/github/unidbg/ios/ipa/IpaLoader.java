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
import org.apache.commons.io.FileUtils;
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

public abstract class IpaLoader {

    private static final Log log = LogFactory.getLog(IpaLoader.class);

    @SuppressWarnings("unused")
    public final LoadedIpa load(String... loads) {
        return load(null, loads);
    }

    public abstract LoadedIpa load(EmulatorConfigurator configurator, String... loads);

    protected final File ipa;
    protected final File rootDir;

    private final String appDir;
    private final String executable;
    private final String bundleVersion;
    private final String bundleIdentifier;

    private final String executableBundlePath;

    IpaLoader(File ipa, File rootDir) {
        this.ipa = ipa;
        this.rootDir = rootDir;

        try {
            this.appDir = parseApp(ipa);
            this.executable = parseExecutable(ipa, appDir);
            this.bundleVersion = parseVersion(ipa, appDir);
            this.bundleIdentifier = parseCFBundleIdentifier(ipa, appDir);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        this.executableBundlePath = generateExecutableBundlePath();
    }

    public static final String APP_DIR = "/var/containers/Bundle/Application/";
    public static final String PAYLOAD_PREFIX = "Payload";

    private String generateExecutableBundlePath() {
        UUID uuid = UUID.nameUUIDFromBytes(DigestUtils.md5(appDir));
        return appDir.replace(PAYLOAD_PREFIX, APP_DIR + uuid.toString().toUpperCase()) + executable;
    }

    private static String parseExecutable(File ipa, String appDir) throws IOException {
        try {
            byte[] data = loadZip(ipa, appDir + "Info.plist");
            if (data == null) {
                throw new IllegalStateException("Find Info.plist failed");
            }
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            NSString bundleExecutable = (NSString) info.get("CFBundleExecutable");
            return bundleExecutable.getContent();
        } catch (PropertyListFormatException | ParseException | ParserConfigurationException | SAXException e) {
            throw new IllegalStateException("load ipa failed", e);
        }
    }

    private static String parseVersion(File ipa, String appDir) throws IOException {
        try {
            byte[] data = loadZip(ipa, appDir + "Info.plist");
            if (data == null) {
                throw new IllegalStateException("Find Info.plist failed");
            }
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            NSString bundleVersion = (NSString) info.get("CFBundleVersion");
            return bundleVersion.getContent();
        } catch (PropertyListFormatException | ParseException | ParserConfigurationException | SAXException e) {
            throw new IllegalStateException("load ipa failed", e);
        }
    }

    private static String parseCFBundleIdentifier(File ipa, String appDir) throws IOException {
        try {
            byte[] data = loadZip(ipa, appDir + "Info.plist");
            if (data == null) {
                throw new IllegalStateException("Find Info.plist failed");
            }
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            NSString bundleIdentifier = (NSString) info.get("CFBundleIdentifier");
            return bundleIdentifier.getContent();
        } catch (PropertyListFormatException | ParseException | ParserConfigurationException | SAXException e) {
            throw new IllegalStateException("load ipa failed", e);
        }
    }

    protected void config(final Emulator<DarwinFileIO> emulator, File ipa, String executableBundlePath, File rootDir) throws IOException {
        File executable = new File(executableBundlePath);
        SyscallHandler<DarwinFileIO> syscallHandler = emulator.getSyscallHandler();
        syscallHandler.setVerbose(log.isDebugEnabled());
        File appDir = executable.getParentFile();
        syscallHandler.addIOResolver(new IpaResolver(appDir.getPath(), ipa));
        FileUtils.forceMkdir(new File(rootDir, appDir.getParentFile().getPath()));
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));
    }

    LoadedIpa load32(EmulatorConfigurator configurator, String... loads) throws IOException {
        String bundleAppDir = new File(executableBundlePath).getParentFile().getParentFile().getPath();
        File rootDir = new File(this.rootDir, bundleVersion);
        Emulator<DarwinFileIO> emulator = new DarwinARMEmulator(executableBundlePath, rootDir, getEnvs());
        if (configurator != null) {
            configurator.configure(emulator, executableBundlePath, rootDir);
        }
        config(emulator, ipa, executableBundlePath, rootDir);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        return load(emulator, ipa, bundleAppDir, loads);
    }

    LoadedIpa load64(EmulatorConfigurator configurator, String... loads) throws IOException {
        String bundleAppDir = new File(executableBundlePath).getParentFile().getParentFile().getPath();
        File rootDir = new File(this.rootDir, bundleVersion);
        Emulator<DarwinFileIO> emulator = new DarwinARM64Emulator(executableBundlePath, rootDir, getEnvs());
        if (configurator != null) {
            configurator.configure(emulator, executableBundlePath, rootDir);
        }
        config(emulator, ipa, executableBundlePath, rootDir);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        return load(emulator, ipa, bundleAppDir, loads);
    }

    protected String[] getEnvs() {
        if (log.isDebugEnabled()) {
            return new String[] {
                    "OBJC_HELP=YES", // describe available environment variables
//                    "OBJC_PRINT_OPTIONS=YES", // list which options are set
//                    "OBJC_PRINT_INITIALIZE_METHODS=YES", // log calls to class +initialize methods
                    "OBJC_PRINT_CLASS_SETUP=YES", // log progress of class and category setup
                    "OBJC_PRINT_PROTOCOL_SETUP=YES", // log progress of protocol setup
                    "OBJC_PRINT_IVAR_SETUP=YES", // log processing of non-fragile ivars
                    "OBJC_PRINT_VTABLE_SETUP=YES", // log processing of class vtables
            };
        } else {
            return new String[0];
        }
    }

    private boolean forceCallInit;

    @SuppressWarnings("unused")
    public void setForceCallInit(boolean forceCallInit) {
        this.forceCallInit = forceCallInit;
    }

    private LoadedIpa load(Emulator<DarwinFileIO> emulator, File ipa, String bundleAppDir, String... loads) throws IOException {
        Memory memory = emulator.getMemory();
        Module module = memory.load(new IpaLibraryFile(appDir, ipa, executable, bundleAppDir, loads), forceCallInit);
        MachOLoader loader = (MachOLoader) memory;
        loader.onExecutableLoaded(executable);
        return new LoadedIpa(emulator, module, bundleIdentifier, bundleVersion);
    }

    private static final Pattern PATTERN = Pattern.compile("^(Payload/\\w+\\.app/)");

    private static String parseApp(File ipa) throws IOException {
        try (JarFile file = new JarFile(ipa)) {
            Enumeration<JarEntry> enumeration = file.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (!entry.getName().startsWith(PAYLOAD_PREFIX)) {
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
