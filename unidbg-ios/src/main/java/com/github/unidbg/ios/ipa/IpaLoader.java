package com.github.unidbg.ios.ipa;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSString;
import com.dd.plist.PropertyListFormatException;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.DarwinARM64Emulator;
import com.github.unidbg.ios.DarwinARMEmulator;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.DarwinSyscallHandler;
import com.github.unidbg.ios.Loader;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

public abstract class IpaLoader implements Loader {

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

    protected final String executableBundlePath;

    IpaLoader(File ipa, File rootDir) {
        this.ipa = ipa;
        this.rootDir = rootDir;

        try {
            this.appDir = parseApp(ipa);
            this.executable = parseExecutable(ipa, appDir);
            this.bundleVersion = parseVersion(ipa, appDir);
            this.bundleIdentifier = parseCFBundleIdentifier(ipa, appDir);
        } catch (IOException e) {
            throw new IllegalStateException("load " + ipa.getAbsolutePath() + " failed", e);
        }
        this.executableBundlePath = generateExecutableBundlePath();
    }

    private String generateRandomSeed() {
        return appDir + bundleIdentifier + "_" + bundleVersion;
    }

    private static final String APP_DIR = "/var/containers/Bundle/Application/";
    public static final String PAYLOAD_PREFIX = "Payload";

    private String generateExecutableBundlePath() {
        UUID uuid = UUID.nameUUIDFromBytes((generateRandomSeed() + "_Application").getBytes(StandardCharsets.UTF_8));
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
        File appDir = executable.getParentFile();
        syscallHandler.addIOResolver(new IpaResolver(appDir.getPath(), ipa));
        FileUtils.forceMkdir(new File(rootDir, appDir.getParentFile().getPath()));
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));

        ((DarwinSyscallHandler) syscallHandler).setExecutableBundlePath(executableBundlePath);
    }

    protected final List<BackendFactory> backendFactories = new ArrayList<>(5);

    public void addBackendFactory(BackendFactory backendFactory) {
        this.backendFactories.add(backendFactory);
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

    protected DarwinResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    private boolean overrideResolver;

    public void useOverrideResolver() {
        this.overrideResolver = true;
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

    public static void addEnv(List<String> list) {
        list.add("OBJC_DISABLE_PREOPTIMIZATION=YES"); // disable preoptimization courtesy of dyld shared cache
        list.add("OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES"); // disable safety checks for +initialize after fork
        list.add("OBJC_DISABLE_TAGGED_POINTERS=YES");
        list.add("OBJC_DISABLE_TAG_OBFUSCATION=YES");
        if (log.isDebugEnabled()) {
            list.add("OBJC_HELP=YES"); // describe available environment variables
            list.add("OBJC_PRINT_OPTIONS=YES"); // list which options are set
            list.add("OBJC_PRINT_CLASS_SETUP=YES"); // log progress of class and category setup
            list.add("OBJC_PRINT_INITIALIZE_METHODS=YES"); // log calls to class +initialize methods
            list.add("OBJC_PRINT_PROTOCOL_SETUP=YES"); // log progress of protocol setup
            list.add("OBJC_PRINT_IVAR_SETUP=YES"); // log processing of non-fragile ivars
            list.add("OBJC_PRINT_VTABLE_SETUP=YES"); // log processing of class vtables

            list.add("OBJC_PRINT_IMAGES=YES"); // log image and library names as they are loaded
            list.add("OBJC_PRINT_IMAGE_TIMES=YES"); // measure duration of image loading steps
            list.add("OBJC_PRINT_LOAD_METHODS=YES"); // log calls to class and category +load methods
            list.add("OBJC_PRINT_RESOLVED_METHODS=YES"); // log methods created by +resolveClassMethod: and +resolveInstanceMethod:
            list.add("OBJC_PRINT_PREOPTIMIZATION=YES"); // log preoptimization courtesy of dyld shared cache
            list.add("OBJC_PRINT_EXCEPTIONS=YES"); // log exception handling
            list.add("OBJC_DEBUG_FRAGILE_SUPERCLASSES=YES"); // warn about subclasses that may have been broken by subsequent changes to superclasses
        }
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

    private boolean forceCallInit;

    @SuppressWarnings("unused")
    public void setForceCallInit(boolean forceCallInit) {
        this.forceCallInit = forceCallInit;
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

    @Override
    public final boolean isPayloadModule(String path) {
        return path.startsWith(APP_DIR);
    }
}
