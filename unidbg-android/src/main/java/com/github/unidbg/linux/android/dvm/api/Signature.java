package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import net.dongliu.apk.parser.bean.CertificateMeta;
import org.apache.commons.codec.binary.Hex;

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

    public String toCharsString() {
        return Hex.encodeHexString(value.getData());
    }

}
