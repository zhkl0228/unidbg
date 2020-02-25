package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.ElfLibraryFile;
import com.github.unidbg.linux.android.dvm.api.Signature;
import com.github.unidbg.spi.LibraryFile;
import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.ApkMeta;
import net.dongliu.apk.parser.bean.ApkSigner;
import net.dongliu.apk.parser.bean.CertificateMeta;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.util.*;

public abstract class BaseVM implements VM {

    private static final Log log = LogFactory.getLog(BaseVM.class);

    final Map<Long, DvmClass> classMap = new HashMap<>();

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
    private final File apkFile;

    final Set<String> notFoundClassSet = new HashSet<>();

    @Override
    public void addNotFoundClass(String className) {
        notFoundClassSet.add(className);
    }

    BaseVM(Emulator<?> emulator, File apkFile) {
        this.emulator = emulator;
        this.apkFile = apkFile;
    }

    final Map<Long, DvmObject<?>> globalObjectMap = new HashMap<>();
    final Map<Long, DvmObject<?>> localObjectMap = new HashMap<>();

    @Override
    public final DvmClass resolveClass(String className, DvmClass... interfaceClasses) {
        long hash = Objects.hash(className) & 0xffffffffL;
        DvmClass dvmClass = classMap.get(hash);
        if (dvmClass == null) {
            dvmClass = new DvmClass(this, className, interfaceClasses);
            classMap.put(hash, dvmClass);
            addObject(dvmClass, true);
        }
        return dvmClass;
    }

    final int addObject(DvmObject<?> object, boolean global) {
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
    public final int addLocalObject(DvmObject<?> object) {
        if (object == null) {
            return JNI_NULL;
        }

        return addObject(object, false);
    }

    @SuppressWarnings("unchecked")
    @Override
    public final <T extends DvmObject<?>> T getObject(long hash) {
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
        public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) throws IOException {
            byte[] libData = findLibrary(apkFile, soName);
            return libData == null ? null : new ApkLibraryFile(apkFile, soName, libData);
        }
        @Override
        public byte[] readToByteArray() {
            return soData;
        }
        @Override
        public ByteBuffer mapBuffer() {
            return ByteBuffer.wrap(soData);
        }
        @Override
        public String getPath() {
            return "/data/app-lib/" + packageName + "-1";
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
            return new DalvikModule(this, module);
        } finally {
            IOUtils.closeQuietly(apkFile);
        }
    }

    private Signature[] signatures;

    Signature[] getSignatures() {
        if (apkFile == null) {
            return null;
        }
        if (signatures != null) {
            return signatures;
        }

        ApkFile apkFile = null;
        try {
            apkFile = new ApkFile(this.apkFile);
            List<Signature> signatures = new ArrayList<>(10);
            for (ApkSigner signer : apkFile.getApkSingers()) {
                for (CertificateMeta meta : signer.getCertificateMetas()) {
                    signatures.add(new Signature(this, meta));
                }
            }
            this.signatures = signatures.toArray(new Signature[0]);
            return this.signatures;
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException(e);
        } finally {
            IOUtils.closeQuietly(apkFile);
        }
    }

    private ApkMeta apkMeta;

    @Override
    public String getPackageName() {
        if (apkFile == null) {
            return null;
        }
        if (apkMeta != null) {
            return apkMeta.getPackageName();
        }

        ApkFile apkFile = null;
        try {
            apkFile = new ApkFile(this.apkFile);
            apkMeta = apkFile.getApkMeta();
            return apkMeta.getPackageName();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            IOUtils.closeQuietly(apkFile);
        }
    }

    @Override
    public String getManifestXml() {
        if (apkFile == null) {
            return null;
        }

        ApkFile apkFile = null;
        try {
            apkFile = new ApkFile(this.apkFile);
            return apkFile.getManifestXml();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            IOUtils.closeQuietly(apkFile);
        }
    }

    @Override
    public byte[] openAsset(String fileName) {
        if (apkFile == null) {
            return null;
        }

        ApkFile apkFile = null;
        try {
            apkFile = new ApkFile(this.apkFile);
            return apkFile.getFileData("assets/" + fileName);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            IOUtils.closeQuietly(apkFile);
        }
    }

    String getVersionName() {
        if (apkFile == null) {
            return null;
        }
        if (apkMeta != null) {
            return apkMeta.getVersionName();
        }

        ApkFile apkFile = null;
        try {
            apkFile = new ApkFile(this.apkFile);
            apkMeta = apkFile.getApkMeta();
            return apkMeta.getVersionName();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            IOUtils.closeQuietly(apkFile);
        }
    }

    @Override
    public final DalvikModule loadLibrary(File elfFile, boolean forceCallInit) throws IOException {
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
}
