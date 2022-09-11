package com.github.unidbg.arm.backend.hypervisor;

abstract class ExceptionVisitor {

    public abstract void onException(Hypervisor hypervisor);

    static ExceptionVisitor breakRestorerVisitor(final BreakRestorer breakRestorer) {
        return new ExceptionVisitor() {
            @Override
            public void onException(Hypervisor hypervisor) {
                breakRestorer.install(hypervisor);
            }
        };
    }

}
