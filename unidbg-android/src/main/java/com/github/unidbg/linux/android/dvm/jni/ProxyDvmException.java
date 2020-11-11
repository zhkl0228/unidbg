package com.github.unidbg.linux.android.dvm.jni;

public abstract class ProxyDvmException extends RuntimeException {

    public ProxyDvmException() {
    }

    public ProxyDvmException(String message) {
        super(message);
    }

    public ProxyDvmException(String message, Throwable cause) {
        super(message, cause);
    }

    public ProxyDvmException(Throwable cause) {
        super(cause);
    }

    public ProxyDvmException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
