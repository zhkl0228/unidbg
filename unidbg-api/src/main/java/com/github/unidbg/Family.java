package com.github.unidbg;

public enum  Family {

    Android32(".so", "/android/lib/armeabi-v7a/"),
    Android64(".so", "/android/lib/arm64-v8a/"),
    iOS(".dylib", "/ios/lib/")
    ;

    private final String libraryExtension;
    private final String libraryPath;

    Family(String libraryExtension, String libraryPath) {
        this.libraryExtension = libraryExtension;
        this.libraryPath = libraryPath;
    }

    public String getLibraryExtension() {
        return libraryExtension;
    }

    public String getLibraryPath() {
        return libraryPath;
    }

}
