package com.github.unidbg.linux.android.dvm.apk;

import net.dongliu.apk.parser.bean.CertificateMeta;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class ApkSigningBlockParserTest {

    private static final String CERT_BASE64 =
            "MIIC0DCCAbigAwIBAgIJALeiZQQIMAYLMA0GCSqGSIb3DQEBDAUAMBYxFDASBgNVBAMTC3VuaWRiZyB0ZXN0MB4XDTI2MTAyODE3" +
            "NDYxMVoXDTM2MTAyNTE3NDYxMVowFjEUMBIGA1UEAxMLdW5pZGJnIHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB" +
            "AQDXvAJDwMAcQlet/inHSFWHjhAT1jSjYfyIrpbaPV0nAxw8Dxs6qufvZmCTnzAjz0TxzxkMMorJ6hnyherCSC+Zam56X09l+2TI" +
            "swhloebqi1Stt29PhzmqUPZbDZE1UsnXsQj1WKY60bU+X8lRMY+yeGYKJCfBXXHdY/8sGFm4WIXLhLMT6ZsS6/8SDx+Vy4q2N045" +
            "l21eYHyHAoNyt8QaM2ZdIeO+b8eJHEEfyRCUp9Q3ae4LaLM2L08w98tEumeMnwDuxhlVzULdK/5Z7sdutC1FdOnKVI3ZRZl4Srq6" +
            "Q4Ms5ME3rHYjBBeRQcu5gEgrdIdFDP6RqKCWEruWwU0hAgMBAAGjITAfMB0GA1UdDgQWBBQWeIEPNY5xwfrKGO6iJCMNnIxLpTAN" +
            "BgkqhkiG9w0BAQwFAAOCAQEAVrLNIrdm+Ywnn8cth2yHXyaD65TcSyNzf4ECU0I3epe7DND77DZHlfh0UKGlh/B7Et1BF3Y2hHzL" +
            "rhkJ2tC8bdfEy6HZeQF0E9lZJB6U0vAJY8bG0mMIzMXzRlapf8Vxps9JOzxdTLjmY3hLwxB6RCARXkEdgYGG9P1PCpGK0cOuw+Ks" +
            "d+zFR9UoVc9JUPu58kdYRedKrA273cobZG9F2mKAzxq0oFMHu0KjrWFGj0NmamTUpKYeTttjutpugowtITT7Xsi0/2BFUPIXniOu" +
            "rRB1N0XKiU4h4AWlapn4VLTWOHVNkCaExjSx/9wlFxTIoklyRwCLK+jq1xPCMS9r8g==";

    @Test
    public void parseV2SignerCertificate() throws Exception {
        byte[] certificate = Base64.getDecoder().decode(CERT_BASE64);
        File apkFile = File.createTempFile("signing-block", ".apk");
        try {
            Files.write(apkFile.toPath(), signedZip(certificate));

            CertificateMeta[] metas = ApkSigningBlockParser.parse(apkFile);

            assertEquals(1, metas.length);
            assertArrayEquals(certificate, metas[0].getData());
        } finally {
            apkFile.delete();
        }
    }

    private static byte[] signedZip(byte[] certificate) throws Exception {
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(zipBytes)) {
            zip.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            zip.write(new byte[]{0x03, 0x00, 0x08, 0x00});
            zip.closeEntry();
        }
        byte[] zip = zipBytes.toByteArray();
        int eocd = findEndOfCentralDirectory(zip);
        int centralDirectoryOffset = ByteBuffer.wrap(zip, eocd + 16, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] block = signingBlock(certificate);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(zip, 0, centralDirectoryOffset);
        out.write(block);
        out.write(zip, centralDirectoryOffset, zip.length - centralDirectoryOffset);
        byte[] result = out.toByteArray();

        int newCentralDirectoryOffset = centralDirectoryOffset + block.length;
        putInt(result, eocd + block.length + 16, newCentralDirectoryOffset);
        putInt(result, newCentralDirectoryOffset + 42, block.length); // 中央目录记录里的本地头偏移
        return result;
    }

    private static byte[] signingBlock(byte[] certificate) {
        byte[] certificateSequence = concat(uint32(certificate.length), certificate);
        byte[] signedData = concat(uint32(0) /* digests */, uint32(certificateSequence.length), certificateSequence);
        byte[] signer = concat(uint32(signedData.length), signedData, uint32(0) /* signatures */);
        byte[] signers = concat(uint32(4 + signer.length), uint32(signer.length), signer);

        byte[] pair = concat(uint64(4 + signers.length), uint32(0x7109871a), signers);
        long size = pair.length + 24;
        byte[] magic = {'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ', 'B', 'l', 'o', 'c', 'k', ' ', '4', '2'};
        return concat(uint64(size), pair, uint64(size), magic);
    }

    private static int findEndOfCentralDirectory(byte[] zip) {
        for (int i = zip.length - 22; i >= 0; i--) {
            if ((zip[i] & 0xff) == 0x50 && (zip[i + 1] & 0xff) == 0x4b
                    && (zip[i + 2] & 0xff) == 0x05 && (zip[i + 3] & 0xff) == 0x06) {
                return i;
            }
        }
        throw new IllegalStateException("EOCD not found");
    }

    private static void putInt(byte[] bytes, int offset, int value) {
        ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(value);
    }

    private static byte[] uint32(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
    }

    private static byte[] uint64(long value) {
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array();
    }

    private static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            out.write(array, 0, array.length);
        }
        return out.toByteArray();
    }

}
