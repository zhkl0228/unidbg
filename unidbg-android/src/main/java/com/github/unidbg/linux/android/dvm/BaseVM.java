package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.ElfLibraryFile;
import com.github.unidbg.linux.android.dvm.api.Signature;
import com.github.unidbg.linux.android.dvm.apk.Apk;
import com.github.unidbg.linux.android.dvm.apk.ApkFactory;
import com.github.unidbg.linux.android.dvm.apk.AssetResolver;
import com.github.unidbg.spi.LibraryFile;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.nio.ByteBuffer;
import java.util.*;

public abstract class BaseVM implements VM, DvmClassFactory {

    private static final Log log = LogFactory.getLog(BaseVM.class);

    final Map<Integer, DvmClass> classMap = new HashMap<>();

    Jni jni;

    DvmObject<?> throwable;

    boolean verbose;

    @Override
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    @Override
    public void throwException(DvmObject<?> throwable) {
        this.throwable = throwable;
    }

    @Override
    public final void setJni(Jni jni) {
        this.jni = jni;
    }

    private final Emulator<?> emulator;
    private final Apk apk;

    final Set<String> notFoundClassSet = new HashSet<>();

    @Override
    public void addNotFoundClass(String className) {
        notFoundClassSet.add(className);
    }

    BaseVM(Emulator<?> emulator, File apkFile) {
        this.emulator = emulator;
        this.apk = apkFile == null ? null : ApkFactory.createApk(apkFile);
    }

    final Map<Integer, DvmObject<?>> globalObjectMap = new HashMap<>();
    final Map<Integer, DvmObject<?>> localObjectMap = new HashMap<>();

    private DvmClassFactory dvmClassFactory;

    @Override
    public void setDvmClassFactory(DvmClassFactory factory) {
        this.dvmClassFactory = factory;
    }

    @Override
    public final DvmClass resolveClass(String className, DvmClass... interfaceClasses) {
        int hash = Objects.hash(className);
        DvmClass dvmClass = classMap.get(hash);
        DvmClass superClass = null;
        if (interfaceClasses != null && interfaceClasses.length > 0) {
            superClass = interfaceClasses[0];
            interfaceClasses = Arrays.copyOfRange(interfaceClasses, 1, interfaceClasses.length);
        }
        if (dvmClass == null) {
            if (dvmClassFactory != null) {
                dvmClass = dvmClassFactory.createClass(this, className, superClass, interfaceClasses);
            }
            if (dvmClass == null) {
                dvmClass = this.createClass(this, className, superClass, interfaceClasses);
            }
            classMap.put(hash, dvmClass);
            addObject(dvmClass, true);
        }
        return dvmClass;
    }

    @Override
    public DvmClass createClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses) {
        return new DvmClass(vm, className, superClass, interfaceClasses);
    }

    final int addObject(DvmObject<?> object, boolean global) {
        if (object == null) {
            return 0;
        } else {
            int hash = object.hashCode();
            if (log.isDebugEnabled()) {
                log.debug("addObject hash=0x" + Long.toHexString(hash));
            }
            if (global) {
                globalObjectMap.put(hash, object);
            } else {
                localObjectMap.put(hash, object);
            }
            return hash;
        }
    }

    @Override
    public final int addLocalObject(DvmObject<?> object) {
        if (object == null) {
            return JNI_NULL;
        }

        return addObject(object, false);
    }

    @SuppressWarnings("unchecked")
    @Override
    public final <T extends DvmObject<?>> T getObject(int hash) {
        if (localObjectMap.containsKey(hash)) {
            return (T) localObjectMap.get(hash);
        } else {
            return (T) globalObjectMap.get(hash);
        }
    }

    @Override
    public final DvmClass findClass(String className) {
        return classMap.get(Objects.hash(className));
    }

    final void deleteLocalRefs() {
        for (DvmObject<?> obj : localObjectMap.values()) {
            obj.onDeleteRef();
        }
        localObjectMap.clear();

        if (throwable != null) {
            throwable.onDeleteRef();
            throwable = null;
        }
    }

    private class ApkLibraryFile implements LibraryFile {
        private final Apk apk;
        private final String soName;
        private final byte[] soData;
        private final String packageName;
        private final String appDir;
        ApkLibraryFile(Apk apk, String soName, byte[] soData, String packageName) {
            this.apk = apk;
            this.soName = soName;
            this.soData = soData;
            this.packageName = packageName;
            this.appDir = packageName == null ? "" : ('/' + packageName + "-1");
        }
        @Override
        public String getName() {
            return soName;
        }
        @Override
        public String getMapRegionName() {
            return "/data/app-lib" + appDir + '/' + soName;
        }
        @Override
        public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
            byte[] libData = loadLibraryData(apk, soName);
            return libData == null ? null : new ApkLibraryFile(this.apk, soName, libData, packageName);
        }
        @Override
        public ByteBuffer mapBuffer() {
            return ByteBuffer.wrap(soData);
        }
        @Override
        public String getPath() {
            return "/data/app-lib" + appDir;
        }
    }

    abstract byte[] loadLibraryData(Apk apk, String soName);

    @Override
    public final DalvikModule loadLibrary(String libname, boolean forceCallInit) {
        if (apk == null) {
            throw new UnsupportedOperationException();
        }

        String soName = "lib" + libname + ".so";
        ApkLibraryFile libraryFile = findLibrary(apk, soName);
        if (libraryFile == null) {
            File split = new File(apk.getParentFile(), emulator.is64Bit() ? "config.arm64_v8a.apk" : "config.armeabi_v7a.apk");
            if (split.canRead()) {
                libraryFile = findLibrary(ApkFactory.createApk(split), soName);
            }
        }
        if (libraryFile == null) {
            throw new IllegalStateException("load library failed: " + libname);
        }

        Module module = emulator.getMemory().load(libraryFile, forceCallInit);
        return new DalvikModule(this, module);
    }

    private ApkLibraryFile findLibrary(Apk apk, String soName) {
        byte[] libData = loadLibraryData(apk, soName);
        if (libData == null) {
            return null;
        }

        return new ApkLibraryFile(apk, soName, libData, apk.getPackageName());
    }

    Signature[] getSignatures() {
        return apk == null ? null : apk.getSignatures(this);
    }

    @Override
    public String getPackageName() {
        return apk == null ? null : apk.getPackageName();
    }

    @Override
    public String getManifestXml() {
        return apk == null ? null : apk.getManifestXml();
    }

    @Override
    public byte[] openAsset(String fileName) {
        if (assetResolver != null) {
            byte[] bytes = assetResolver.resolveAsset(fileName);
            if (bytes != null) {
                return bytes;
            }
        }

        return apk == null ? null : apk.openAsset(fileName);
    }

    private AssetResolver assetResolver;

    @Override
    public void setAssetResolver(AssetResolver assetResolver) {
        this.assetResolver = assetResolver;
    }

    @Override
    public final String getVersionName() {
        return apk == null ? null : apk.getVersionName();
    }

    @Override
    public long getVersionCode() {
        return apk == null ? 0 : apk.getVersionCode();
    }

    @Override
    public final DalvikModule loadLibrary(File elfFile, boolean forceCallInit) {
        Module module = emulator.getMemory().load(new ElfLibraryFile(elfFile), forceCallInit);
        return new DalvikModule(this, module);
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
    public void callJNI_OnLoad(Emulator<?> emulator, Module module) {
        new DalvikModule(this, module).callJNI_OnLoad(emulator);
    }

    @Override
    public Emulator<?> getEmulator() {
        return emulator;
    }
}
