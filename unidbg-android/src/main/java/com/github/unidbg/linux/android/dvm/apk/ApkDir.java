package com.github.unidbg.linux.android.dvm.apk;

import net.dongliu.apk.parser.bean.ApkMeta;
import net.dongliu.apk.parser.bean.ApkSigner;
import net.dongliu.apk.parser.bean.CertificateMeta;
import net.dongliu.apk.parser.parser.ApkMetaTranslator;
import net.dongliu.apk.parser.parser.BinaryXmlParser;
import net.dongliu.apk.parser.parser.CertificateParser;
import net.dongliu.apk.parser.parser.CompositeXmlStreamer;
import net.dongliu.apk.parser.parser.XmlStreamer;
import net.dongliu.apk.parser.parser.XmlTranslator;
import net.dongliu.apk.parser.struct.AndroidConstants;
import net.dongliu.apk.parser.struct.resource.ResourceTable;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

class ApkDir implements Apk {

    private final File dir;

    ApkDir(File dir) {
        this.dir = dir;
    }

    @Override
    public long getVersionCode() {
        parseManifest();
        return apkMeta == null ? 0L : apkMeta.getVersionCode();
    }

    @Override
    public String getVersionName() {
        parseManifest();
        return apkMeta == null ? null : apkMeta.getVersionName();
    }

    @Override
    public String getManifestXml() {
        parseManifest();
        return manifestXml;
    }

    @Override
    public byte[] openAsset(String fileName) {
        return getFileData("assets/" + fileName);
    }

    @Override
    public byte[] getFileData(String path) {
        File file = new File(dir, path);
        if (file.canRead()) {
            try {
                return FileUtils.readFileToByteArray(file);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        } else {
            return null;
        }
    }

    private CertificateMeta[] signatures;

    @Override
    public CertificateMeta[] getSignatures() {
        if (signatures == null) {
            try {
                parseCertificates();
            } catch (IOException | CertificateException e) {
                throw new IllegalStateException(e);
            }
        }
        return this.signatures;
    }

    private static class CertificateFile {
        private final String path;
        private final byte[] data;

        CertificateFile(String path, byte[] data) {
            this.path = path;
            this.data = data;
        }

        public String getPath() {
            return path;
        }

        public byte[] getData() {
            return data;
        }
    }

    private List<CertificateFile> getAllCertificateData() throws IOException {
        List<CertificateFile> list = new ArrayList<>();
        scanCertificateFile(list, dir);
        return list;
    }

    private void scanCertificateFile(List<CertificateFile> list, File dir) throws IOException {
        File[] files = dir.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                String ext;
                return pathname.isDirectory() || (ext = FilenameUtils.getExtension(pathname.getName())).equalsIgnoreCase("RSA") || ext.equalsIgnoreCase("DSA");
            }
        });
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    scanCertificateFile(list, file);
                } else {
                    list.add(new CertificateFile(file.getPath(), FileUtils.readFileToByteArray(file)));
                }
            }
        }
    }

    private void parseCertificates() throws IOException, CertificateException {
        List<ApkSigner> apkSigners = new ArrayList<>();
        for (CertificateFile file : getAllCertificateData()) {
            CertificateParser parser = CertificateParser.getInstance(file.getData());
            List<CertificateMeta> certificateMetas = parser.parse();
            apkSigners.add(new ApkSigner(file.getPath(), certificateMetas));
        }
        List<CertificateMeta> signatures = new ArrayList<>(apkSigners.size());
        for (ApkSigner signer : apkSigners) {
            signatures.addAll(signer.getCertificateMetas());
        }
        this.signatures = signatures.toArray(new CertificateMeta[0]);
    }

    @Override
    public String getPackageName() {
        parseManifest();
        return apkMeta == null ? null : apkMeta.getPackageName();
    }

    @Override
    public File getParentFile() {
        return dir.getParentFile();
    }

    private boolean manifestParsed;

    private String manifestXml;
    private ApkMeta apkMeta;

    private void parseManifest() {
        if (manifestParsed) {
            return;
        }
        ResourceTable resourceTable = new ResourceTable();
        Locale preferredLocale = Locale.US;
        XmlTranslator xmlTranslator = new XmlTranslator();
        ApkMetaTranslator apkTranslator = new ApkMetaTranslator(resourceTable, preferredLocale);
        XmlStreamer xmlStreamer = new CompositeXmlStreamer(xmlTranslator, apkTranslator);

        byte[] data = getFileData(AndroidConstants.MANIFEST_FILE);
        if (data != null) {
            transBinaryXml(data, xmlStreamer, resourceTable, preferredLocale);
            this.manifestXml = xmlTranslator.getXml();
            this.apkMeta = apkTranslator.getApkMeta();
            manifestParsed = true;
        }
    }

    private void transBinaryXml(byte[] data, XmlStreamer xmlStreamer, ResourceTable resourceTable, Locale preferredLocale) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        BinaryXmlParser binaryXmlParser = new BinaryXmlParser(buffer, resourceTable);
        binaryXmlParser.setLocale(preferredLocale);
        binaryXmlParser.setXmlStreamer(xmlStreamer);
        binaryXmlParser.parse();
    }

}
