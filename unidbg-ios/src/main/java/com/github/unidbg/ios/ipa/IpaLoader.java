package com.github.unidbg.ios.ipa;

import com.dd.plist.NSDictionary;
import com.dd.plist.PropertyListFormatException;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.BaseLoader;
import com.github.unidbg.ios.DarwinARM64Emulator;
import com.github.unidbg.ios.DarwinARMEmulator;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.DarwinSyscallHandler;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class IpaLoader extends BaseLoader {

    private static final Logger log = LoggerFactory.getLogger(IpaLoader.class);

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

    protected final String executableBundlePath;

    IpaLoader(Class<?> callingClass, File rootDir) {
        this(new File(callingClass.getProtectionDomain().getCodeSource().getLocation().getPath()), rootDir);
    }

    IpaLoader(File ipa, File rootDir) {
        this.ipa = ipa;
        this.rootDir = rootDir;

        try {
            this.appDir = parseApp(ipa);

            byte[] data = loadZip(ipa, appDir + "Info.plist");
            if (data == null) {
                throw new IllegalStateException("Find Info.plist failed");
            }
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            this.executable = parseExecutable(info);
            this.bundleVersion = parseVersion(info);
            this.bundleIdentifier = parseCFBundleIdentifier(info);
        } catch (IOException | PropertyListFormatException | ParseException | ParserConfigurationException |
                 SAXException e) {
            throw new IllegalStateException("load " + ipa.getAbsolutePath() + " failed", e);
        }
        this.executableBundlePath = generateExecutableBundlePath();
    }

    private String generateRandomSeed() {
        return appDir + bundleIdentifier + "_" + bundleVersion;
    }

    public static final String PAYLOAD_PREFIX = "Payload";

    private String generateExecutableBundlePath() {
        UUID uuid = UUID.nameUUIDFromBytes((generateRandomSeed() + "_Application").getBytes(StandardCharsets.UTF_8));
        return appDir.replace(PAYLOAD_PREFIX, APP_DIR + uuid.toString().toUpperCase()) + executable;
    }

    protected void config(final Emulator<DarwinFileIO> emulator, File ipa, String executableBundlePath, File rootDir) throws IOException {
        File executable = new File(executableBundlePath);
        SyscallHandler<DarwinFileIO> syscallHandler = emulator.getSyscallHandler();
        File appDir = executable.getParentFile();
        syscallHandler.addIOResolver(new IpaResolver(appDir.getPath(), ipa));
        FileUtils.forceMkdir(new File(rootDir, appDir.getParentFile().getPath()));
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));

        ((DarwinSyscallHandler) syscallHandler).setExecutableBundlePath(executableBundlePath);
    }

    protected Emulator<DarwinFileIO> createEmulator(File rootDir, boolean is64Bit) throws IOException {
        if (is64Bit) {
            return new DarwinARM64Emulator(executableBundlePath, rootDir, backendFactories, getEnvs(rootDir)) {
            };
        } else {
            return new DarwinARMEmulator(executableBundlePath, rootDir, backendFactories, getEnvs(rootDir)) {
            };
        }
    }

    LoadedIpa load32(EmulatorConfigurator configurator, String... loads) throws IOException {
        String bundleAppDir = new File(executableBundlePath).getParentFile().getParentFile().getPath();
        File rootDir = new File(this.rootDir, bundleVersion);
        Emulator<DarwinFileIO> emulator = createEmulator(rootDir, false);
        emulator.getSyscallHandler().setVerbose(log.isDebugEnabled());
        if (configurator != null) {
            configurator.configure(emulator, executableBundlePath, rootDir, bundleIdentifier);
        }
        config(emulator, ipa, executableBundlePath, rootDir);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        return load(emulator, ipa, bundleAppDir, configurator, loads);
    }

    LoadedIpa load64(EmulatorConfigurator configurator, String... loads) throws IOException {
        String bundleAppDir = new File(executableBundlePath).getParentFile().getParentFile().getPath();
        File rootDir = new File(this.rootDir, bundleVersion);
        Emulator<DarwinFileIO> emulator = createEmulator(rootDir, true);
        emulator.getSyscallHandler().setVerbose(log.isDebugEnabled());
        if (configurator != null) {
            configurator.configure(emulator, executableBundlePath, rootDir, bundleIdentifier);
        }
        config(emulator, ipa, executableBundlePath, rootDir);
        Memory memory = emulator.getMemory();
        DarwinResolver resolver = createLibraryResolver();
        if (overrideResolver) {
            resolver.setOverride();
        }
        memory.setLibraryResolver(resolver);
        return load(emulator, ipa, bundleAppDir, configurator, loads);
    }

    protected String[] getEnvs(File rootDir) throws IOException {
        List<String> list = new ArrayList<>();
        list.add("OBJC_PRINT_EXCEPTION_THROW=YES"); // log backtrace of every objc_exception_throw()
        addEnv(list);
        UUID uuid = UUID.nameUUIDFromBytes((generateRandomSeed() + "_Documents").getBytes(StandardCharsets.UTF_8));
        String homeDir = "/var/mobile/Containers/Data/Application/" + uuid.toString().toUpperCase();
        list.add("CFFIXED_USER_HOME=" + homeDir);
        FileUtils.forceMkdir(new File(rootDir, homeDir));
        return list.toArray(new String[0]);
    }

    private LoadedIpa load(Emulator<DarwinFileIO> emulator, File ipa, String bundleAppDir, EmulatorConfigurator configurator, String... loads) throws IOException {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setLoader(this);
        Module module = loader.load(new IpaLibraryFile(appDir, ipa, executable, bundleAppDir, loads), forceCallInit);
        if (configurator != null) {
            configurator.onExecutableLoaded(emulator, (MachOModule) module);
        }
        loader.onExecutableLoaded(executable);
        return new LoadedIpa(emulator, module, bundleIdentifier, bundleVersion);
    }

    private static final Pattern PATTERN = Pattern.compile("^(Payload/[\\w一-龥]+\\.app/)"); // 支持中文

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

    @Override
    public final boolean isPayloadModule(String path) {
        return path.startsWith(APP_DIR);
    }
}
