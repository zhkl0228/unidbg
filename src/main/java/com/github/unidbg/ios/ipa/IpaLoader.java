package com.github.unidbg.ios.ipa;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSString;
import com.dd.plist.PropertyListFormatException;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.ios.DarwinARM64Emulator;
import com.github.unidbg.ios.DarwinARMEmulator;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
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

    public abstract void callEntry();

    public abstract Module getExecutable();

    public abstract Emulator<DarwinFileIO> getEmulator();

    private static String getProcessName(File ipa) throws IOException {
        String appDir = parseApp(ipa);
        String executable = parseExecutable(ipa, appDir);
        UUID uuid = UUID.nameUUIDFromBytes(DigestUtils.md5(appDir));
        return appDir.replace("Payload", "/var/containers/Bundle/Application/" + uuid.toString().toUpperCase()) + executable;
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

    private static void config(final Emulator<DarwinFileIO> emulator, File ipa, String processName, File rootDir) throws IOException {
        File executable = new File(processName);
        SyscallHandler<DarwinFileIO> syscallHandler = emulator.getSyscallHandler();
        syscallHandler.setVerbose(log.isDebugEnabled());
        File appDir = executable.getParentFile();
        syscallHandler.addIOResolver(new IpaResolver(appDir.getAbsolutePath(), ipa));
        FileUtils.forceMkdir(new File(rootDir, appDir.getParentFile().getAbsolutePath()));
        emulator.getMemory().addHookListener(new HookListener() {
            private UnicornPointer _os_unfair_lock_lock, _os_unfair_lock_unlock;
            @Override
            public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
                if ("_os_unfair_lock_lock".equals(symbolName)) {
                    if (_os_unfair_lock_lock == null) {
                        _os_unfair_lock_lock = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                            @Override
                            public long handle(Emulator<?> emulator) {
                                return 0;
                            }
                        } : new ArmSvc() {
                            @Override
                            public long handle(Emulator<?> emulator) {
                                return 0;
                            }
                        });
                    }
                    return _os_unfair_lock_lock.peer;
                }
                if ("_os_unfair_lock_unlock".equals(symbolName)) {
                    if (_os_unfair_lock_unlock == null) {
                        _os_unfair_lock_unlock = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                            @Override
                            public long handle(Emulator<?> emulator) {
                                return 0;
                            }
                        } : new ArmSvc() {
                            @Override
                            public long handle(Emulator<?> emulator) {
                                return 0;
                            }
                        });
                    }
                    return _os_unfair_lock_unlock.peer;
                }
                return 0;
            }
        });
    }

    @SuppressWarnings("unused")
    public static IpaLoader load32(File ipa, File rootDir, String... loads) throws IOException {
        String processName = getProcessName(ipa);
        Emulator<DarwinFileIO> emulator = new DarwinARMEmulator(processName, rootDir, getEnvs());
        config(emulator, ipa, processName, rootDir);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        return load(emulator, ipa, false, loads);
    }

    @SuppressWarnings("unused")
    public static IpaLoader load64(File ipa, File rootDir, String... loads) throws IOException {
        String processName = getProcessName(ipa);
        Emulator<DarwinFileIO> emulator = new DarwinARM64Emulator(processName, rootDir, getEnvs());
        config(emulator, ipa, processName, rootDir);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        return load(emulator, ipa, false, loads);
    }

    private static String[] getEnvs() {
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

    public static IpaLoader load(Emulator<DarwinFileIO> emulator, File ipa, String... loads) throws IOException {
        return load(emulator, ipa, false, loads);
    }

    public static IpaLoader load(Emulator<DarwinFileIO> emulator, File ipa, boolean forceCallInit, String... loads) throws IOException {
        String appDir = parseApp(ipa);
        String executable = parseExecutable(ipa, appDir);
        Memory memory = emulator.getMemory();
        Module module = memory.load(new IpaLibraryFile(appDir, ipa, executable, loads), forceCallInit);
        MachOLoader loader = (MachOLoader) memory;
        loader.onExecutableLoaded(executable);
        return new IpaLoaderImpl(emulator, module);
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
