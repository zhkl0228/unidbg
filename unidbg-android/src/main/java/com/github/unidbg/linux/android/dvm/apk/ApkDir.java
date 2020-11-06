package com.github.unidbg.linux.android.dvm.apk;

import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.api.Signature;
import net.dongliu.apk.parser.bean.ApkMeta;
import net.dongliu.apk.parser.bean.ApkSigner;
import net.dongliu.apk.parser.bean.CertificateMeta;
import net.dongliu.apk.parser.exception.ParserException;
import net.dongliu.apk.parser.parser.*;
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
        return apkMeta.getVersionCode();
    }

    @Override
    public String getVersionName() {
        parseManifest();
        return apkMeta.getVersionName();
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

    private Signature[] signatures;

    @Override
    public Signature[] getSignatures(VM vm) {
        if (signatures == null) {
            try {
                parseCertificates(vm);
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

    private void parseCertificates(VM vm) throws IOException, CertificateException {
        List<ApkSigner> apkSigners = new ArrayList<>();
        for (CertificateFile file : getAllCertificateData()) {
            CertificateParser parser = CertificateParser.getInstance(file.getData());
            List<CertificateMeta> certificateMetas = parser.parse();
            apkSigners.add(new ApkSigner(file.getPath(), certificateMetas));
        }
        List<Signature> signatures = new ArrayList<>(apkSigners.size());
        for (ApkSigner signer : apkSigners) {
            for (CertificateMeta meta : signer.getCertificateMetas()) {
                signatures.add(new Signature(vm, meta));
            }
        }
        this.signatures = signatures.toArray(new Signature[0]);
    }

    @Override
    public String getPackageName() {
        parseManifest();
        return apkMeta.getPackageName();
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
        if (data == null) {
            throw new ParserException("Manifest file not found");
        }
        transBinaryXml(data, xmlStreamer, resourceTable, preferredLocale);
        this.manifestXml = xmlTranslator.getXml();
        this.apkMeta = apkTranslator.getApkMeta();
        manifestParsed = true;
    }

    private void transBinaryXml(byte[] data, XmlStreamer xmlStreamer, ResourceTable resourceTable, Locale preferredLocale) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        BinaryXmlParser binaryXmlParser = new BinaryXmlParser(buffer, resourceTable);
        binaryXmlParser.setLocale(preferredLocale);
        binaryXmlParser.setXmlStreamer(xmlStreamer);
        binaryXmlParser.parse();
    }

}
