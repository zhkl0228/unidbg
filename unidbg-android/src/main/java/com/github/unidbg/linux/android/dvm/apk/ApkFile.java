package com.github.unidbg.linux.android.dvm.apk;

import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.api.Signature;
import net.dongliu.apk.parser.bean.ApkMeta;
import net.dongliu.apk.parser.bean.ApkSigner;
import net.dongliu.apk.parser.bean.CertificateMeta;

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

    private Signature[] signatures;

    @Override
    public Signature[] getSignatures(VM vm) {
        if (signatures != null) {
            return signatures;
        }

        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            List<Signature> signatures = new ArrayList<>(10);
            for (ApkSigner signer : apkFile.getApkSingers()) {
                for (CertificateMeta meta : signer.getCertificateMetas()) {
                    signatures.add(new Signature(vm, meta));
                }
            }
            this.signatures = signatures.toArray(new Signature[0]);
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
        } catch (IOException e) {
            throw new IllegalStateException(e);
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
