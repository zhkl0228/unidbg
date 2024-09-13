package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.ElfLibraryFile;
import com.github.unidbg.linux.android.ElfLibraryRawFile;
import com.github.unidbg.linux.android.dvm.apk.Apk;
import com.github.unidbg.linux.android.dvm.apk.ApkFactory;
import com.github.unidbg.linux.android.dvm.apk.AssetResolver;
import com.github.unidbg.spi.LibraryFile;
import net.dongliu.apk.parser.bean.CertificateMeta;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public abstract class BaseVM implements VM, DvmClassFactory {

    private static final Logger log = LoggerFactory.getLogger(BaseVM.class);

    public static boolean valueOf(int value) {
        if (value == VM.JNI_TRUE) {
            return true;
        } else if (value == VM.JNI_FALSE) {
            return false;
        } else {
            throw new IllegalStateException("Invalid boolean value=" + value);
        }
    }

    final Map<Integer, DvmClass> classMap = new HashMap<>();

    Jni jni;

    DvmObject<?> throwable;

    boolean verbose, verboseMethodOperation, verboseFieldOperation;

    @Override
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    @Override
    public void setVerboseMethodOperation(boolean verboseMethodOperation) {
        this.verboseMethodOperation = verboseMethodOperation;
    }

    @Override
    public void setVerboseFieldOperation(boolean verboseFieldOperation) {
        this.verboseFieldOperation = verboseFieldOperation;
    }

    @Override
    public void throwException(DvmObject<?> throwable) {
        this.throwable = throwable;
    }

    @Override
    public final void setJni(Jni jni) {
        this.jni = jni;
    }

    private final AndroidEmulator emulator;
    private final Apk apk;

    final Set<String> notFoundClassSet = new HashSet<>();

    @Override
    public void addNotFoundClass(String className) {
        notFoundClassSet.add(className);
    }

    BaseVM(AndroidEmulator emulator, File apkFile) {
        this.emulator = emulator;
        this.apk = apkFile == null ? null : ApkFactory.createApk(apkFile);
    }

    final static class ObjRef {
        final DvmObject<?> obj;
        final boolean weak;
        ObjRef(DvmObject<?> obj, boolean weak) {
            this.obj = obj;
            this.weak = weak;
            this.refCount = 1;
        }
        int refCount;
        @Override
        public String toString() {
            return String.valueOf(obj);
        }
    }

    final Map<Integer, ObjRef> globalObjectMap = new HashMap<>();
    final Map<Integer, ObjRef> weakGlobalObjectMap = new HashMap<>();
    final Map<Integer, ObjRef> localObjectMap = new HashMap<>();

    private DvmClassFactory dvmClassFactory;

    @Override
    public void setDvmClassFactory(DvmClassFactory factory) {
        this.dvmClassFactory = factory;
    }

    @Override
    public final DvmClass resolveClass(String className, DvmClass... interfaceClasses) {
        className = className.replace('.', '/');
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
        }
        addGlobalObject(dvmClass);
        return dvmClass;
    }

    @Override
    public DvmClass createClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses) {
        return new DvmClass(vm, className, superClass, interfaceClasses);
    }

    final int addObject(DvmObject<?> object, boolean global, boolean weak) {
        int hash = object.hashCode();
        if (log.isDebugEnabled()) {
            log.debug("addObject hash=0x{}, global={}", Long.toHexString(hash), global);
        }
        Object value = object.getValue();
        if (value instanceof DvmAwareObject) {
            ((DvmAwareObject) value).initializeDvm(emulator, this, object);
        }
        if (global) {
            ObjRef old = weak ? weakGlobalObjectMap.get(hash) : globalObjectMap.get(hash);
            if (old == null) {
                old = new ObjRef(object, weak);
            } else {
                old.refCount++;
            }
            if (weak) {
                weakGlobalObjectMap.put(hash, old);
            } else {
                globalObjectMap.put(hash, old);
            }
        } else {
            localObjectMap.put(hash, new ObjRef(object, weak));
        }
        return hash;
    }

    @Override
    public final int addLocalObject(DvmObject<?> object) {
        if (object == null) {
            return JNI_NULL;
        }

        return addObject(object, false, false);
    }

    @Override
    public final int addGlobalObject(DvmObject<?> object) {
        if (object == null) {
            return JNI_NULL;
        }

        return addObject(object, true, false);
    }

    @SuppressWarnings("unchecked")
    @Override
    public final <T extends DvmObject<?>> T getObject(int hash) {
        ObjRef ref;
        if (localObjectMap.containsKey(hash)) {
            ref = localObjectMap.get(hash);
        } else if(globalObjectMap.containsKey(hash)) {
            ref = globalObjectMap.get(hash);
        } else {
            ref = weakGlobalObjectMap.get(hash);
        }
        return ref == null ? null : (T) ref.obj;
    }

    @Override
    public final DvmClass findClass(String className) {
        return classMap.get(Objects.hash(className));
    }

    final void deleteLocalRefs() {
        for (ObjRef ref : localObjectMap.values()) {
            ref.obj.onDeleteRef();
        }
        localObjectMap.clear();

        if (throwable != null) {
            throwable.onDeleteRef();
            throwable = null;
        }
    }

    final void checkVersion(int version) {
        if (version != JNI_VERSION_1_1 &&
                version != JNI_VERSION_1_2 &&
                version != JNI_VERSION_1_4 &&
                version != JNI_VERSION_1_6 &&
                version != JNI_VERSION_1_8) {
            if (log.isTraceEnabled()) {
                emulator.attach().debug();
            }
            throw new IllegalStateException("Illegal JNI version: 0x" + Integer.toHexString(version));
        }
    }

    abstract byte[] loadLibraryData(Apk apk, String soName);

    @Override
    public LibraryFile findLibrary(String soName) {
        if (apk == null) {
            throw new UnsupportedOperationException();
        }

        ApkLibraryFile libraryFile = findLibrary(apk, soName);
        if (libraryFile == null) {
            File split = new File(apk.getParentFile(), emulator.is64Bit() ? "config.arm64_v8a.apk" : "config.armeabi_v7a.apk");
            if (split.canRead()) {
                libraryFile = findLibrary(ApkFactory.createApk(split), soName);
            }
        }
        return libraryFile;
    }

    @Override
    public final DalvikModule loadLibrary(String libname, boolean forceCallInit) {
        String soName = "lib" + libname + ".so";
        LibraryFile libraryFile = findLibrary(soName);
        if (libraryFile == null) {
            throw new IllegalStateException("load library failed: " + libname);
        }
        Module module = emulator.getMemory().load(libraryFile, forceCallInit);
        return new DalvikModule(this, module);
    }

    @Override
    public final DalvikModule loadLibrary(String libname, byte[] raw, boolean forceCallInit) {
        if (raw == null || raw.length == 0) {
            throw new IllegalArgumentException();
        }
        Module module = emulator.getMemory().load(new ElfLibraryRawFile(libname, raw, emulator.is64Bit()), forceCallInit);
        return new DalvikModule(this, module);
    }

    private ApkLibraryFile findLibrary(Apk apk, String soName) {
        byte[] libData = loadLibraryData(apk, soName);
        if (libData == null) {
            return null;
        }

        return new ApkLibraryFile(this, apk, soName, libData, apk.getPackageName(), emulator.is64Bit());
    }

    @Override
    public CertificateMeta[] getSignatures() {
        return apk == null ? null : apk.getSignatures();
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

    @Override
    public byte[] unzip(String path) {
        if (path.length() > 1 && path.charAt(0) == '/') {
            path = path.substring(1);
        }
        return apk == null ? null : apk.getFileData(path);
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
        Module module = emulator.getMemory().load(new ElfLibraryFile(elfFile, emulator.is64Bit()), forceCallInit);
        return new DalvikModule(this, module);
    }

    @Override
    public final void printMemoryInfo() {
        System.gc();
        MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage heap = memoryMXBean.getHeapMemoryUsage();
        MemoryUsage nonHeap = memoryMXBean.getNonHeapMemoryUsage();
        Map<Integer, ObjRef> map = new HashMap<>(globalObjectMap);
        for (Integer key : classMap.keySet()) {
            map.remove(key);
        }
        System.err.println("globalObjectSize=" + globalObjectMap.size() + ", localObjectSize=" + localObjectMap.size() + ", weakGlobalObjectSize=" + weakGlobalObjectMap.size() + ", classSize=" + classMap.size() + ", globalObjectSize=" + map.size());
        System.err.println("heap: " + memoryUsage(heap) + ", nonHeap: " + memoryUsage(nonHeap));
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
