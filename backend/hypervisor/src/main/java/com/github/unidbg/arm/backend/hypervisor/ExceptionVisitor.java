package com.github.unidbg.arm.backend.hypervisor;

abstract class ExceptionVisitor {

    public abstract boolean onException(Hypervisor hypervisor, int ec, long address);

    static ExceptionVisitor breakRestorerVisitor(final BreakRestorer breakRestorer) {
        return new ExceptionVisitor() {
            @Override
            public boolean onException(Hypervisor hypervisor, int ec, long address) {
                breakRestorer.install(hypervisor);
                return false;
            }
        };
    }

}
