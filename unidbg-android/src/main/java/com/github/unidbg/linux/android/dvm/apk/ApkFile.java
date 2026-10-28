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

        List<CertificateMeta> v1Signatures = new ArrayList<>(10);
        try (net.dongliu.apk.parser.ApkFile apkFile = new net.dongliu.apk.parser.ApkFile(this.apkFile)) {
            for (ApkSigner signer : apkFile.getApkSingers()) {
                v1Signatures.addAll(signer.getCertificateMetas());
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (CertificateException ignored) { // 没有 v1 签名
        }

        if (!v1Signatures.isEmpty()) {
            this.signatures = v1Signatures.toArray(new CertificateMeta[0]);
        } else {
            this.signatures = ApkSigningBlockParser.parse(this.apkFile);
        }
        return this.signatures;
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
