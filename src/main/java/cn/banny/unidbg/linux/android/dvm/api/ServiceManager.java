package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;

public class ServiceManager extends DvmObject<String> {

    public ServiceManager(DvmClass objectType, String value) {
        super(objectType, value);
    }

    public DvmObject getService(VM vm, String serviceName) {
        return new SystemService(vm, serviceName);
    }
}
