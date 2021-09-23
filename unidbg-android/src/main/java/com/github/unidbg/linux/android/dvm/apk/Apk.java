package com.github.unidbg.linux.android.dvm.apk;

import net.dongliu.apk.parser.bean.CertificateMeta;

import java.io.File;

public interface Apk {

    long getVersionCode();

    String getVersionName();

    String getManifestXml();

    byte[] openAsset(String fileName);

    CertificateMeta[] getSignatures();

    String getPackageName();

    File getParentFile();

    byte[] getFileData(String path);

}
