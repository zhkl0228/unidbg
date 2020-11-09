package com.github.unidbg.linux.android.dvm.jni;

class ProxyClassLoader {

    private final ClassLoader classLoader;

    ProxyClassLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    private ClassNameMapper classNameMapper;

    final void setClassNameMapper(ClassNameMapper classNameMapper) {
        this.classNameMapper = classNameMapper;
    }

    final Class<?> loadClass(String name) throws ClassNotFoundException {
        String newName = classNameMapper == null ? null : classNameMapper.map(name);
        if (newName != null) {
            name = newName;
        }
        return classLoader.loadClass(name);
    }

}
