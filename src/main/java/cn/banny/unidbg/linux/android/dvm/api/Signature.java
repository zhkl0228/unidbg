package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.utils.Hex;
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

    public String toCharsString() {
        return Hex.encodeHexString(value.getData());
    }

}
