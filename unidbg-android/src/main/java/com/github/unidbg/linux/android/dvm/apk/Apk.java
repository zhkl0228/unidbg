package com.github.unidbg.linux.android.dvm.apk;

import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.api.Signature;

import java.io.File;

public interface Apk {

    long getVersionCode();

    String getVersionName();

    String getManifestXml();

    byte[] openAsset(String fileName);

    Signature[] getSignatures(VM vm);

    String getPackageName();

    File getParentFile();

    byte[] getFileData(String path);

}
