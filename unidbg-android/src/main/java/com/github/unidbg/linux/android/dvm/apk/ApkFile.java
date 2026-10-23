package com.github.unidbg.linux.android.dvm.apk;

import net.dongliu.apk.parser.bean.ApkMeta;
import net.dongliu.apk.parser.bean.ApkSigner;
import net.dongliu.apk.parser.bean.CertificateMeta;
import net.dongliu.apk.parser.exception.ParserException;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

class ApkFile implements Apk {

    private final File apkFile;

    ApkFile(File file) {
        this.apkFile = file;
    }

    private ApkMeta apkMeta;

    @Override
    public long getVersionCode() {
        if (apkMeta != null) {
            return apkMeta.getVersionCode();
        }

        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            apkMeta = apkFile.getApkMeta();
            return apkMeta.getVersionCode();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getVersionName() {
        if (apkMeta != null) {
            return apkMeta.getVersionName();
        }

        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            apkMeta = apkFile.getApkMeta();
            return apkMeta.getVersionName();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getManifestXml() {
        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            return apkFile.getManifestXml();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public byte[] openAsset(String fileName) {
        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            return apkFile.getFileData("assets/" + fileName);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private CertificateMeta[] signatures;

    @Override
    public CertificateMeta[] getSignatures() {
        if (signatures != null) {
            return signatures;
        }

        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            List<CertificateMeta> signatures = new ArrayList<>(10);
            for (ApkSigner signer : apkFile.getApkSingers()) {
                signatures.addAll(signer.getCertificateMetas());
            }
            this.signatures = signatures.toArray(new CertificateMeta[0]);
            return this.signatures;
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getPackageName() {
        if (apkMeta != null) {
            return apkMeta.getPackageName();
        }

        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            apkMeta = apkFile.getApkMeta();
            return apkMeta.getPackageName();
        } catch (ParserException e) { // Manifest file not found
            return null;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (RuntimeException e) {
            // A truncated/minimal resources.arsc -- e.g. the stub table aapt2
            // emits for a resource-less app -- makes apk-parser's full parse
            // throw (typically a BufferUnderflowException) before it ever reaches
            // the package name. The package name is a literal attribute on the
            // <manifest> element and needs no resource table, so read it straight
            // from the binary AndroidManifest.xml.
            String packageName = parsePackageFromBinaryManifest();
            if (packageName != null) {
                return packageName;
            }
            throw e;
        }
    }

    private String parsePackageFromBinaryManifest() {
        try {
            byte[] axml = getFileData("AndroidManifest.xml");
            return axml == null ? null : extractPackageFromAxml(axml);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    /**
     * Read the {@code package} attribute of the {@code <manifest>} element from a
     * binary AndroidManifest.xml, without consulting the resource table.
     */
    private static String extractPackageFromAxml(byte[] axml) {
        java.nio.ByteBuffer b = java.nio.ByteBuffer.wrap(axml).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        if (b.remaining() < 8) {
            return null;
        }
        b.getInt(); // magic 0x00080003
        b.getInt(); // file size
        int poolStart = b.position();
        if ((b.getShort() & 0xFFFF) != 0x0001) { // RES_STRING_POOL_TYPE
            return null;
        }
        b.getShort(); // header size
        int chunkSize = b.getInt();
        int stringCount = b.getInt();
        b.getInt(); // style count
        boolean utf8 = (b.getInt() & (1 << 8)) != 0; // UTF8_FLAG
        int stringsStart = b.getInt();
        b.getInt(); // styles start
        int[] offsets = new int[stringCount];
        for (int i = 0; i < stringCount; i++) {
            offsets[i] = b.getInt();
        }
        int stringsBase = poolStart + stringsStart;
        String[] strings = new String[stringCount];
        for (int i = 0; i < stringCount; i++) {
            strings[i] = readAxmlString(axml, stringsBase + offsets[i], utf8);
        }
        int pos = poolStart + chunkSize;
        while (pos + 8 <= axml.length) {
            b.position(pos);
            int type = b.getShort() & 0xFFFF;
            b.getShort();
            int size = b.getInt();
            if (type == 0x0102) { // RES_XML_START_ELEMENT_TYPE
                b.getInt(); // line number
                b.getInt(); // comment
                b.getInt(); // namespace
                int nameIdx = b.getInt();
                b.getShort(); // attribute start
                b.getShort(); // attribute size
                int attrCount = b.getShort() & 0xFFFF;
                b.getShort(); b.getShort(); b.getShort(); // id/class/style index
                String element = axmlString(strings, nameIdx);
                for (int i = 0; i < attrCount; i++) {
                    b.getInt(); // namespace
                    int an = b.getInt(); // name
                    int rawValue = b.getInt(); // raw value string index
                    b.getShort(); b.getShort(); b.getInt(); // typed value
                    if ("manifest".equals(element) && "package".equals(axmlString(strings, an))) {
                        return rawValue >= 0 ? axmlString(strings, rawValue) : null;
                    }
                }
            }
            if (size <= 0) {
                break;
            }
            pos += size;
        }
        return null;
    }

    private static String axmlString(String[] strings, int index) {
        return (index >= 0 && index < strings.length) ? strings[index] : null;
    }

    private static String readAxmlString(byte[] d, int off, boolean utf8) {
        try {
            if (utf8) {
                int p = off;
                p += ((d[p] & 0x80) != 0) ? 2 : 1; // skip the char-count field
                int n = d[p++] & 0xFF; // byte length
                if ((n & 0x80) != 0) {
                    n = (n & 0x7F) << 8 | (d[p++] & 0xFF);
                }
                return new String(d, p, n, java.nio.charset.StandardCharsets.UTF_8);
            } else {
                int n = (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8);
                int start = off + 2;
                if ((n & 0x8000) != 0) {
                    n = ((n & 0x7FFF) << 16) | ((d[off + 2] & 0xFF) | ((d[off + 3] & 0xFF) << 8));
                    start = off + 4;
                }
                return new String(d, start, n * 2, java.nio.charset.StandardCharsets.UTF_16LE);
            }
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Override
    public File getParentFile() {
        return apkFile.getParentFile();
    }

    @Override
    public byte[] getFileData(String path) {
        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            return apkFile.getFileData(path);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
