package com.github.unidbg.ios.dmg;

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
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
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

public abstract class DmgLoader extends BaseLoader {

    private static final Logger log = LoggerFactory.getLogger(DmgLoader.class);

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

    protected void config(final Emulator<DarwinFileIO> emulator, File dmgDir) {
        SyscallHandler<DarwinFileIO> syscallHandler = emulator.getSyscallHandler();
        syscallHandler.addIOResolver(new DmgResolver(dmgDir));
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));
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
        DarwinResolver resolver = createLibraryResolver();
        if (overrideResolver) {
            resolver.setOverride();
        }
        memory.setLibraryResolver(resolver);
        return load(emulator, bundleAppDir, configurator, loads);
    }

    protected String[] getEnvs(File rootDir) throws IOException {
        List<String> list = new ArrayList<>();
        list.add("OBJC_PRINT_EXCEPTION_THROW=YES"); // log backtrace of every objc_exception_throw()
        addEnv(list);
        UUID uuid = UUID.nameUUIDFromBytes((bundleIdentifier + "_Documents").getBytes(StandardCharsets.UTF_8));
        String homeDir = "/var/mobile/Containers/Data/Application/" + uuid.toString().toUpperCase();
        list.add("CFFIXED_USER_HOME=" + homeDir);
        FileUtils.forceMkdir(new File(rootDir, homeDir));
        return list.toArray(new String[0]);
    }

    private LoadedDmg load(Emulator<DarwinFileIO> emulator, String bundleAppDir, EmulatorConfigurator configurator, String... loads) {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setLoader(this);
        File executableFile = new File(executableBundlePath);
        Module module = loader.load(new DmgLibraryFile(executableFile.getParent(), executable, bundleAppDir, executableFile, loads), forceCallInit);
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
