package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;
import net.dongliu.apk.parser.bean.CertificateMeta;

import java.util.Arrays;

public class Signature extends DvmObject<CertificateMeta> {

    public Signature(VM vm, CertificateMeta meta) {
        super(vm.resolveClass("android/content/pm/Signature"), meta);
    }

    public int getHashCode() {
        return Arrays.hashCode(value.getData());
    }

    public byte[] toByteArray() {
        return value.getData();
    }

    /**
     * Encode the Signature as ASCII text in to an existing array.
     *
     * @return Returns either <var>existingArray</var> if it was large enough
     * to hold the ASCII representation, or a newly created char[] array if
     * needed.
     */
    private char[] toChars() {
        byte[] sig = value.getData();
        final int N = sig.length;
        final int N2 = N*2;
        char[] text = new char[N2];
        for (int j=0; j<N; j++) {
            byte v = sig[j];
            int d = (v>>4)&0xf;
            text[j*2] = (char)(d >= 10 ? ('a' + d - 10) : ('0' + d));
            d = v&0xf;
            text[j*2+1] = (char)(d >= 10 ? ('a' + d - 10) : ('0' + d));
        }
        return text;
    }

    /**
     * Return the result of {@link #toChars()} as a String.
     */
    public String toCharsString() {
        return new String(toChars());
    }

}
