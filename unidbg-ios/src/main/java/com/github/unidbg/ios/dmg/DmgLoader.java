package com.github.unidbg.ios.dmg;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSString;
import com.dd.plist.PropertyListFormatException;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.DarwinARM64Emulator;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.Loader;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public abstract class DmgLoader implements Loader {

    private static final Log log = LogFactory.getLog(DmgLoader.class);

    @SuppressWarnings("unused")
    public final LoadedDmg load(String... loads) {
        return load(null, loads);
    }

    public abstract LoadedDmg load(EmulatorConfigurator configurator, String... loads);

    private final String appDir;
    protected final File dmgDir;
    protected final File rootDir;

    private final String executable;
    private final String bundleVersion;
    private final String bundleIdentifier;

    protected final String executableBundlePath;

    DmgLoader(File dmgDir, File rootDir) {
        this.dmgDir = dmgDir;
        this.rootDir = rootDir;
        this.appDir = FilenameUtils.normalize(dmgDir.getPath(), true);

        File infoFile = new File(dmgDir, "Contents/Info.plist");
        if (!infoFile.exists() || !infoFile.isFile()) {
            throw new IllegalStateException("Invalid dmg app dir: " + dmgDir);
        }

        try {
            NSDictionary info = (NSDictionary) PropertyListParser.parse(infoFile);
            this.executable = parseExecutable(info);
            this.bundleVersion = parseVersion(info);
            this.bundleIdentifier = parseCFBundleIdentifier(info);
        } catch (IOException | PropertyListFormatException | ParseException | ParserConfigurationException | SAXException e) {
            throw new IllegalStateException("load " + dmgDir.getAbsolutePath() + " failed", e);
        }
        this.executableBundlePath = generateExecutableBundlePath();
    }

    private String generateExecutableBundlePath() {
        File executable = new File(dmgDir, "Contents/MacOS/" + this.executable);
        if (!executable.exists() || !executable.isFile()) {
            throw new IllegalStateException("Invalid executable: " + executable);
        }
        return executable.getAbsolutePath();
    }

    private static String parseExecutable(NSDictionary info) throws IOException {
        NSString bundleExecutable = (NSString) info.get("CFBundleExecutable");
        return bundleExecutable.getContent();
    }

    private static String parseVersion(NSDictionary info) throws IOException {
        NSString bundleVersion = (NSString) info.get("CFBundleVersion");
        return bundleVersion.getContent();
    }

    private static String parseCFBundleIdentifier(NSDictionary info) throws IOException {
        NSString bundleIdentifier = (NSString) info.get("CFBundleIdentifier");
        return bundleIdentifier.getContent();
    }

    protected void config(final Emulator<DarwinFileIO> emulator, File dmgDir) {
        SyscallHandler<DarwinFileIO> syscallHandler = emulator.getSyscallHandler();
        syscallHandler.addIOResolver(new DmgResolver(dmgDir));
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));
    }

    protected final List<BackendFactory> backendFactories = new ArrayList<>(5);

    public void addBackendFactory(BackendFactory backendFactory) {
        this.backendFactories.add(backendFactory);
    }

    protected Emulator<DarwinFileIO> createEmulator(File rootDir) throws IOException {
        return new DarwinARM64Emulator(executableBundlePath, rootDir, backendFactories, getEnvs(rootDir)) {
        };
    }

    LoadedDmg load64(EmulatorConfigurator configurator, String... loads) throws IOException {
        String bundleAppDir = new File(executableBundlePath).getParentFile().getParentFile().getPath();
        File rootDir = new File(this.rootDir, bundleVersion);
        Emulator<DarwinFileIO> emulator = createEmulator(rootDir);
        emulator.getSyscallHandler().setVerbose(log.isDebugEnabled());
        if (configurator != null) {
            configurator.configure(emulator, executableBundlePath, rootDir, bundleIdentifier);
        }
        config(emulator, dmgDir);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        return load(emulator, bundleAppDir, configurator, loads);
    }

    protected String[] getEnvs(File rootDir) throws IOException {
        List<String> list = new ArrayList<>();
        list.add("PrintExceptionThrow=YES"); // log backtrace of every objc_exception_throw()
        if (log.isDebugEnabled()) {
            list.add("OBJC_HELP=YES"); // describe available environment variables
//            list.add("OBJC_PRINT_OPTIONS=YES"); // list which options are set
            list.add("OBJC_PRINT_CLASS_SETUP=YES"); // log progress of class and category setup
//            list.add("OBJC_PRINT_INITIALIZE_METHODS=YES"); // log calls to class +initialize methods
            list.add("OBJC_PRINT_PROTOCOL_SETUP=YES"); // log progress of protocol setup
            list.add("OBJC_PRINT_IVAR_SETUP=YES"); // log processing of non-fragile ivars
            list.add("OBJC_PRINT_VTABLE_SETUP=YES"); // log processing of class vtables
        }
        UUID uuid = UUID.nameUUIDFromBytes((bundleIdentifier + "_Documents").getBytes(StandardCharsets.UTF_8));
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

    private LoadedDmg load(Emulator<DarwinFileIO> emulator, String bundleAppDir, EmulatorConfigurator configurator, String... loads) throws IOException {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setLoader(this);
        Module module = loader.load(new DmgLibraryFile(executable, bundleAppDir, new File(executableBundlePath), loads), forceCallInit);
        if (configurator != null) {
            configurator.onExecutableLoaded(emulator, (MachOModule) module);
        }
        loader.onExecutableLoaded(executable);
        return new LoadedDmg(emulator, module, bundleIdentifier, bundleVersion);
    }

    @Override
    public final boolean isPayloadModule(String path) {
        return path.startsWith(appDir);
    }

}
