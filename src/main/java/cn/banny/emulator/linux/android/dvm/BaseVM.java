package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.LibraryFile;
import cn.banny.emulator.Module;
import cn.banny.emulator.linux.LinuxModule;
import cn.banny.emulator.linux.android.ElfLibraryFile;
import net.dongliu.apk.parser.ApkFile;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public abstract class BaseVM implements VM {

    private static final Log log = LogFactory.getLog(BaseVM.class);

    final Map<Long, DvmClass> classMap = new HashMap<>();

    Jni jni;

    DvmObject<?> jthrowable;

    @Override
    public final void setJni(Jni jni) {
        this.jni = jni;
    }

    private final Emulator emulator;
    private final File apkFile;

    BaseVM(Emulator emulator, File apkFile) {
        this.emulator = emulator;
        this.apkFile = apkFile;
    }

    final Map<Long, DvmObject> globalObjectMap = new HashMap<>();
    final Map<Long, DvmObject> localObjectMap = new HashMap<>();

    @Override
    public final DvmClass resolveClass(String className) {
        long hash = Objects.hash(className) & 0xffffffffL;
        DvmClass dvmClass = classMap.get(hash);
        if (dvmClass != null) {
            return dvmClass;
        } else {
            dvmClass = new DvmClass(this, className);
            classMap.put(hash, dvmClass);
            addObject(dvmClass, true);
            return dvmClass;
        }
    }

    final int addObject(DvmObject object, boolean global) {
        if (object == null) {
            return 0;
        } else {
            long hash = object.hashCode() & 0xffffffffL;
            if (log.isDebugEnabled()) {
                log.debug("addObject hash=0x" + Long.toHexString(hash));
            }
            if (global) {
                globalObjectMap.put(hash, object);
            } else {
                localObjectMap.put(hash, object);
            }
            return (int) hash;
        }
    }

    @Override
    public final int addLocalObject(DvmObject object) {
        if (object == null) {
            return VM.JNI_NULL;
        }

        return addObject(object, false);
    }

    @SuppressWarnings("unchecked")
    @Override
    public final <T extends DvmObject> T getObject(long hash) {
        if (localObjectMap.containsKey(hash)) {
            return (T) localObjectMap.get(hash);
        } else {
            return (T) globalObjectMap.get(hash);
        }
    }

    @Override
    public final DvmClass findClass(String className) {
        return classMap.get(Objects.hash(className) & 0xffffffffL);
    }

    @Override
    public final void deleteLocalRefs() {
        localObjectMap.clear();
    }

    private class ApkLibraryFile implements LibraryFile {
        private final ApkFile apkFile;
        private final String soName;
        private final byte[] soData;
        private final String packageName;
        ApkLibraryFile(ApkFile apkFile, String soName, byte[] soData) throws IOException {
            this.apkFile = apkFile;
            this.soName = soName;
            this.soData = soData;
            this.packageName = apkFile.getApkMeta().getPackageName();
        }
        @Override
        public String getName() {
            return soName;
        }
        @Override
        public String getMapRegionName() {
            return "/data/app-lib/" + packageName + "-1/" + soName;
        }
        @Override
        public LibraryFile resolveLibrary(Emulator emulator, String soName) throws IOException {
            byte[] libData = findLibrary(apkFile, soName);
            return libData == null ? null : new ApkLibraryFile(apkFile, soName, libData);
        }
        @Override
        public byte[] readToByteArray() {
            return soData;
        }
    }

    abstract byte[] findLibrary(ApkFile apkFile, String soName) throws IOException;

    @Override
    public final DalvikModule loadLibrary(String libname, boolean forceCallInit) throws IOException {
        if (apkFile == null) {
            throw new UnsupportedOperationException();
        }

        String soName = "lib" + libname + ".so";
        ApkFile apkFile = null;
        try {
            apkFile = new ApkFile(this.apkFile);

            byte[] libData = findLibrary(apkFile, soName);
            if (libData == null) {
                throw new IOException("load library failed: " + libname);
            }

            Module module = emulator.getMemory().load(new ApkLibraryFile(apkFile, soName, libData), forceCallInit);
            return new DalvikModule(this, (LinuxModule) module);
        } finally {
            IOUtils.closeQuietly(apkFile);
        }
    }

    @Override
    public final DalvikModule loadLibrary(File elfFile, boolean forceCallInit) throws IOException {
        emulator.setWorkDir(elfFile.getParentFile());

        Module module = emulator.getMemory().load(new ElfLibraryFile(elfFile), forceCallInit);
        return new DalvikModule(this, (LinuxModule) module);
    }

    @Override
    public final void printMemoryInfo() {
        System.gc();
        MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage heap = memoryMXBean.getHeapMemoryUsage();
        MemoryUsage nonheap = memoryMXBean.getNonHeapMemoryUsage();
        System.err.println("globalObjectSize=" + globalObjectMap.size() + ", localObjectSize=" + localObjectMap.size() + ", classSize=" + classMap.size());
        System.err.println("heap: " + memoryUsage(heap) + ", nonheap: " + memoryUsage(nonheap));
    }

    private String toMB(long memory) {
        return (memory * 100 / (1024 * 1024)) / 100F + "MB";
    }

    private String memoryUsage(MemoryUsage usage) {
        return "init=" + toMB(usage.getInit()) + ", used="
                + toMB(usage.getUsed()) + ", committed="
                + toMB(usage.getCommitted()) + ", max="
                + toMB(usage.getMax());
    }

    @Override
    public void callJNI_OnLoad(Emulator emulator, Module module) throws IOException {
        new DalvikModule(this, module).callJNI_OnLoad(emulator);
    }
}
