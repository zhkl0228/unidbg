package com.github.unidbg.linux.android.dvm.apk;

import net.dongliu.apk.parser.bean.CertificateMeta;
import net.dongliu.apk.parser.parser.CertificateMetas;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 从 APK Signing Block 中读取 v2/v3 签名证书，不做摘要校验，重打包的 APK 同样可用。
 */
final class ApkSigningBlockParser {

    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;
    private static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;

    private static final byte[] APK_SIG_BLOCK_MAGIC = {
            'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ',
            'B', 'l', 'o', 'c', 'k', ' ', '4', '2'
    };

    private static final int EOCD_SIG = 0x06054b50;
    private static final int EOCD_MIN_SIZE = 22;
    private static final int MAX_COMMENT_SIZE = 0xffff;

    private ApkSigningBlockParser() {
    }

    static CertificateMeta[] parse(File apkFile) {
        List<X509Certificate> certificates;
        try {
            certificates = parseSigningBlock(readSigningBlock(apkFile));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        if (certificates.isEmpty()) {
            return new CertificateMeta[0];
        }

        try {
            return CertificateMetas.from(certificates).toArray(new CertificateMeta[0]);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] readSigningBlock(File apkFile) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            long centralDirectoryOffset = findCentralDirectoryOffset(raf);
            if (centralDirectoryOffset < 24) {
                return null;
            }

            byte[] footer = new byte[24];
            raf.seek(centralDirectoryOffset - footer.length);
            raf.readFully(footer);
            for (int i = 0; i < APK_SIG_BLOCK_MAGIC.length; i++) {
                if (footer[8 + i] != APK_SIG_BLOCK_MAGIC[i]) {
                    return null;
                }
            }

            long size = readUInt64(footer, 0);
            long blockStart = centralDirectoryOffset - size - 8;
            if (size < footer.length || blockStart < 0 || size + 8 > Integer.MAX_VALUE) {
                return null;
            }
            byte[] block = new byte[(int) size + 8];
            raf.seek(blockStart);
            raf.readFully(block);
            return block;
        }
    }

    private static long findCentralDirectoryOffset(RandomAccessFile raf) throws IOException {
        long fileSize = raf.length();
        int searchSize = (int) Math.min(fileSize, EOCD_MIN_SIZE + MAX_COMMENT_SIZE);
        byte[] tail = new byte[searchSize];
        raf.seek(fileSize - searchSize);
        raf.readFully(tail);

        for (int i = tail.length - EOCD_MIN_SIZE; i >= 0; i--) {
            if (readUInt32(tail, i) != EOCD_SIG) {
                continue;
            }
            long offset = readUInt32(tail, i + 16);
            if (offset == 0xffffffffL) { // ZIP64，暂不支持
                return -1;
            }
            return offset;
        }
        return -1;
    }

    private static List<X509Certificate> parseSigningBlock(byte[] block) {
        if (block == null) {
            return Collections.emptyList();
        }

        ByteBuffer buffer = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
        long size = buffer.getLong();
        if (size != block.length - 8) {
            return Collections.emptyList();
        }

        int pairsEnd = block.length - 24;
        ByteBuffer v2Block = null;
        ByteBuffer v3Block = null;
        int position = 8;
        while (position + 12 <= pairsEnd) {
            buffer.position(position);
            long length = buffer.getLong();
            if (length < 4 || position + 8 + length > pairsEnd) {
                break;
            }
            int id = buffer.getInt();
            ByteBuffer value = slice(buffer, (int) length - 4);
            if (id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID) {
                v3Block = value;
            } else if (id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
                v2Block = value;
            }
            position += 8 + length;
        }
        ByteBuffer signers = v3Block != null ? v3Block : v2Block; // v3 优先
        return signers == null ? Collections.<X509Certificate>emptyList() : parseSigners(signers);
    }

    private static List<X509Certificate> parseSigners(ByteBuffer signers) {
        if (signers.remaining() < 4) {
            return Collections.emptyList();
        }

        List<X509Certificate> certificates = new ArrayList<>(2);
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }

        ByteBuffer sequence = slice(signers, signers.getInt());
        while (sequence.remaining() >= 4) {
            ByteBuffer signer = slice(sequence, sequence.getInt());
            ByteBuffer signedData = slice(signer, signer.getInt());
            skip(signedData, signedData.getInt()); // digests
            ByteBuffer chain = slice(signedData, signedData.getInt()); // certificates，首个为签名者
            if (chain.remaining() < 4) {
                continue;
            }
            byte[] der = new byte[chain.getInt()];
            chain.get(der);
            try {
                certificates.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            } catch (CertificateException e) {
                throw new IllegalStateException(e);
            }
        }
        return certificates;
    }

    private static ByteBuffer slice(ByteBuffer buffer, int length) {
        if (length < 0 || length > buffer.remaining()) {
            throw new IllegalStateException("length=" + length + ", remaining=" + buffer.remaining());
        }
        ByteBuffer slice = buffer.slice().order(ByteOrder.LITTLE_ENDIAN);
        slice.limit(length);
        buffer.position(buffer.position() + length);
        return slice;
    }

    private static void skip(ByteBuffer buffer, int length) {
        if (length < 0 || length > buffer.remaining()) {
            throw new IllegalStateException("length=" + length + ", remaining=" + buffer.remaining());
        }
        buffer.position(buffer.position() + length);
    }

    private static long readUInt32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffL) | ((bytes[offset + 1] & 0xffL) << 8) | ((bytes[offset + 2] & 0xffL) << 16) | ((bytes[offset + 3] & 0xffL) << 24);
    }

    private static long readUInt64(byte[] bytes, int offset) {
        long low = readUInt32(bytes, offset);
        long high = readUInt32(bytes, offset + 4);
        return (high << 32) | low;
    }

}
