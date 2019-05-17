package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;

public class ServiceManager extends DvmObject<String> {

    public ServiceManager(VM vm, String value) {
        super(vm.resolveClass("android/os/IServiceManager"), value);
    }

    public DvmObject getService(VM vm, String serviceName) {
        return new SystemService(vm, serviceName);
    }
}
