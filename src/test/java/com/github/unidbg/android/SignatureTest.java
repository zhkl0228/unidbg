package com.github.unidbg.android;

import junit.framework.TestCase;
import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.ApkSigner;
import net.dongliu.apk.parser.bean.CertificateMeta;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.util.Arrays;

public class SignatureTest extends TestCase {

    public void testSignature() throws Exception {
        ApkFile apkFile = new ApkFile(new File("src/test/resources/app/com.xingin.xhs_5.44.0.apk"));
        for (ApkSigner signer : apkFile.getApkSingers()) {
            for (CertificateMeta meta : signer.getCertificateMetas()) {
                System.out.println("signer path=" + signer.getPath() + ", signAlgorithm=" + meta.getSignAlgorithm() + ", certBase64Md5=" + meta.getCertBase64Md5() + ", certMd5=" + meta.getCertMd5() + ", signAlgorithmOID=" + meta.getSignAlgorithmOID() + ", data=" + Hex.encodeHexString(meta.getData()) + ", hash=" + Arrays.hashCode(meta.getData()));
            }
        }
        apkFile.close();
    }

}
