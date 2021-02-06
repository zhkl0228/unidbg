package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.kvm.Kvm;
import com.github.unidbg.arm.backend.kvm.KvmCallback;
import com.github.unidbg.arm.backend.kvm.KvmException;
import org.apache.commons.io.IOUtils;

public abstract class KvmBackend extends FastBackend implements Backend, KvmCallback {

    protected final Kvm kvm;

    protected KvmBackend(Emulator<?> emulator, Kvm kvm) throws BackendException {
        super(emulator);
        this.kvm = kvm;
        try {
            this.kvm.setKvmCallback(this);
        } catch (KvmException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public final void destroy() throws BackendException {
        IOUtils.closeQuietly(kvm);
    }
}
