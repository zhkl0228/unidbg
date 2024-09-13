package com.github.unidbg.ios.ipa;

import com.dd.plist.NSDictionary;
import com.dd.plist.PropertyListFormatException;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.BaseLoader;
import com.github.unidbg.ios.DarwinARM64Emulator;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class BundleLoader extends BaseLoader {

    private static final Logger log = LoggerFactory.getLogger(BundleLoader.class);

    public static final String APP_NAME = "UniDbg";

    private final File frameworkDir;
    protected final File rootDir;

    public BundleLoader(File frameworkDir, File rootDir) {
        this.frameworkDir = frameworkDir;
        this.rootDir = rootDir;

        if (!frameworkDir.exists() || !frameworkDir.isDirectory()) {
            throw new IllegalArgumentException("Invalid frameworkDir: " + frameworkDir);
        }
    }

    private String generateRandomSeed(String bundleIdentifier, String bundleVersion) {
        return bundleIdentifier + "_" + bundleVersion;
    }

    private String generateExecutableBundlePath(String bundleIdentifier, String bundleVersion) {
        String seed = generateRandomSeed(bundleIdentifier, bundleVersion);
        UUID uuid = UUID.nameUUIDFromBytes((seed + "_Application").getBytes(StandardCharsets.UTF_8));
        return APP_DIR + uuid.toString().toUpperCase() + "/" + APP_NAME + ".app";
    }

    public LoadedBundle load(String name, EmulatorConfigurator configurator) {
        final File bundleDir = new File(this.frameworkDir, name + ".framework");
        String executable;
        String bundleVersion;
        String bundleIdentifier;
        try {
            File infoFile = new File(bundleDir, "Info.plist");
            if (!infoFile.canRead()) {
                throw new IllegalStateException("load " + name + " failed");
            }
            byte[] data = FileUtils.readFileToByteArray(infoFile);
            NSDictionary info = (NSDictionary) PropertyListParser.parse(data);
            executable = parseExecutable(info);
            bundleVersion = parseVersion(info);
            bundleIdentifier = parseCFBundleIdentifier(info);
        } catch (IOException | PropertyListFormatException | ParseException | ParserConfigurationException |
                 SAXException e) {
            throw new IllegalStateException("load " + name + " failed", e);
        }

        String executableBundleDir = generateExecutableBundlePath(bundleIdentifier, bundleVersion);
        String executableBundlePath = executableBundleDir + "/" + APP_NAME;
//        String bundleAppDir = new File(executableBundlePath).getParentFile().getParentFile().getPath();
        File rootDir = new File(this.rootDir, bundleVersion);
        try {
            Emulator<DarwinFileIO> emulator = new DarwinARM64Emulator(executableBundlePath, rootDir, backendFactories, getEnvs(rootDir, executableBundlePath)) {
            };
            emulator.getSyscallHandler().setVerbose(log.isDebugEnabled());
            if (configurator != null) {
                configurator.configure(emulator, executableBundlePath, rootDir, bundleIdentifier);
            }
            config(emulator, executableBundlePath, rootDir);
            MachOLoader memory = (MachOLoader) emulator.getMemory();
            memory.setObjcRuntime(true);
            DarwinResolver resolver = createLibraryResolver();
            if (overrideResolver) {
                resolver.setOverride();
            }
            memory.setLibraryResolver(resolver);
            Module module = load(emulator, configurator, new File(bundleDir, executable), executableBundleDir);
            return new LoadedBundle(emulator, module, bundleIdentifier, bundleVersion);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected void config(final Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir) throws IOException {
        File executable = new File(executableBundlePath);
        SyscallHandler<DarwinFileIO> syscallHandler = emulator.getSyscallHandler();
        File appDir = executable.getParentFile();
        syscallHandler.addIOResolver(new BundleResolver(appDir.getPath(), getBundleIdentifier()));
        FileUtils.forceMkdir(new File(rootDir, appDir.getParentFile().getPath()));
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));

//        ((DarwinSyscallHandler) syscallHandler).setExecutableBundlePath(executableBundlePath);
    }

    protected String getBundleIdentifier() {
        return getClass().getPackage().getName();
    }

    protected String[] getEnvs(File rootDir, String seed) throws IOException {
        List<String> list = new ArrayList<>();
        list.add("OBJC_PRINT_EXCEPTION_THROW=YES"); // log backtrace of every objc_exception_throw()
        addEnv(list);
        UUID uuid = UUID.nameUUIDFromBytes((seed + "_Documents").getBytes(StandardCharsets.UTF_8));
        String homeDir = "/var/mobile/Containers/Data/Application/" + uuid.toString().toUpperCase();
        list.add("CFFIXED_USER_HOME=" + homeDir);
        FileUtils.forceMkdir(new File(rootDir, homeDir + "/Documents"));
        return list.toArray(new String[0]);
    }

    private Module load(Emulator<DarwinFileIO> emulator, EmulatorConfigurator configurator, File executable, String executableBundleDir) throws IOException {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setLoader(this);
        Module module = loader.load(new BundleLibraryFile(executable, executableBundleDir), forceCallInit);
        if (configurator != null) {
            configurator.onExecutableLoaded(emulator, (MachOModule) module);
        }
        loader.onExecutableLoaded(executable.getName());
        return module;
    }

    @Override
    public boolean isPayloadModule(String path) {
        return false;
    }

}
