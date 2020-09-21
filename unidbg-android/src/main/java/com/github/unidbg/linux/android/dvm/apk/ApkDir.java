package com.github.unidbg.linux.android.dvm.apk;

import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.api.Signature;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

class ApkDir implements Apk {

    private final File dir;

    ApkDir(File dir) {
        this.dir = dir;
    }

    @Override
    public long getVersionCode() {
        return 0;
    }

    @Override
    public String getVersionName() {
        return null;
    }

    @Override
    public String getManifestXml() {
        return null;
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

    @Override
    public Signature[] getSignatures(VM vm) {
        return null;
    }

    @Override
    public String getPackageName() {
        return null;
    }

    @Override
    public File getParentFile() {
        return dir.getParentFile();
    }
}
