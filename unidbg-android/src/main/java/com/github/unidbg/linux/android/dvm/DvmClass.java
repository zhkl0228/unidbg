package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class DvmClass extends DvmObject<Class<?>> {

    private static final Log log = LogFactory.getLog(DvmClass.class);

    private static final String ROOT_CLASS = "java/lang/Class";

    public final BaseVM vm;
    private final DvmClass superClass;
    private final DvmClass[] interfaceClasses;
    private final String className;

    protected DvmClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses) {
        this(vm, className, superClass, interfaceClasses, null);
    }

    protected DvmClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses, Class<?> value) {
        super(ROOT_CLASS.equals(className) ? null : vm.resolveClass(ROOT_CLASS), value);
        this.vm = vm;
        this.superClass = superClass;
        this.interfaceClasses = interfaceClasses;
        this.className = className;
    }

    @SuppressWarnings("unused")
    public DvmClass getSuperclass() {
        return superClass;
    }

    @SuppressWarnings("unused")
    public DvmClass[] getInterfaces() {
        return interfaceClasses;
    }

    @Override
    public DvmClass getObjectType() {
        if (ROOT_CLASS.equals(className)) {
            return this;
        }

        return super.getObjectType();
    }

    public String getClassName() {
        return className;
    }

    public String getName() {
        return className.replace('/', '.');
    }

    public DvmObject<?> newObject(Object value) {
        DvmObject<?> obj = new DvmObject<>(this, value);
        vm.addObject(obj, false);
        return obj;
    }

    DvmObject<?> allocObject() {
        String signature = this.getClassName() + "->allocObject";
        if (log.isDebugEnabled()) {
            log.debug("allocObject signature=" + signature);
        }
        BaseVM vm = this.vm;
        return checkJni(vm, this).allocObject(vm, this, signature);
    }

    private final Map<Integer, DvmMethod> staticMethodMap = new HashMap<>();

    final DvmMethod getStaticMethod(int hash) {
        DvmMethod method = staticMethodMap.get(hash);
        if (method == null && superClass != null) {
            method = superClass.getStaticMethod(hash);
        }
        if (method == null) {
            for (DvmClass interfaceClass : interfaceClasses) {
                method = interfaceClass.getStaticMethod(hash);
                if (method != null) {
                    break;
                }
            }
        }
        return method;
    }

    int getStaticMethodID(String methodName, String args) {
        String signature = getClassName() + "->" + methodName + args;
        int hash = signature.hashCode();
        if (log.isDebugEnabled()) {
            log.debug("getStaticMethodID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (checkJni(vm, this).acceptMethod(this, signature, true)) {
            if (!staticMethodMap.containsKey(hash)) {
                staticMethodMap.put(hash, new DvmMethod(this, methodName, args, true));
            }
            return hash;
        } else {
            return 0;
        }
    }

    private final Map<Integer, DvmMethod> methodMap = new HashMap<>();

    final DvmMethod getMethod(int hash) {
        DvmMethod method = methodMap.get(hash);
        if (method == null && superClass != null) {
            method = superClass.getMethod(hash);
        }
        if (method == null) {
            for (DvmClass interfaceClass : interfaceClasses) {
                method = interfaceClass.getMethod(hash);
                if (method != null) {
                    break;
                }
            }
        }
        return method;
    }

    int getMethodID(String methodName, String args) {
        String signature = getClassName() + "->" + methodName + args;
        int hash = signature.hashCode();
        if (log.isDebugEnabled()) {
            log.debug("getMethodID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (vm.jni == null || vm.jni.acceptMethod(this, signature, false)) {
            if (!methodMap.containsKey(hash)) {
                methodMap.put(hash, new DvmMethod(this, methodName, args, false));
            }
            return hash;
        } else {
            return 0;
        }
    }

    private final Map<Integer, DvmField> fieldMap = new HashMap<>();

    final DvmField getField(int hash) {
        DvmField field = fieldMap.get(hash);
        if (field == null && superClass != null) {
            field = superClass.getField(hash);
        }
        if (field == null) {
            for (DvmClass interfaceClass : interfaceClasses) {
                field = interfaceClass.getField(hash);
                if (field != null) {
                    break;
                }
            }
        }
        return field;
    }

    int getFieldID(String fieldName, String fieldType) {
        String signature = getClassName() + "->" + fieldName + ":" + fieldType;
        int hash = signature.hashCode();
        if (log.isDebugEnabled()) {
            log.debug("getFieldID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (vm.jni == null || vm.jni.acceptField(this, signature, false)) {
            if (!fieldMap.containsKey(hash)) {
                fieldMap.put(hash, new DvmField(this, fieldName, fieldType, false));
            }
            return hash;
        } else {
            return 0;
        }
    }

    private final Map<Integer, DvmField> staticFieldMap = new HashMap<>();

    final DvmField getStaticField(int hash) {
        DvmField field = staticFieldMap.get(hash);
        if (field == null && superClass != null) {
            field = superClass.getStaticField(hash);
        }
        if (field == null) {
            for (DvmClass interfaceClass : interfaceClasses) {
                field = interfaceClass.getStaticField(hash);
                if (field != null) {
                    break;
                }
            }
        }
        return field;
    }

    int getStaticFieldID(String fieldName, String fieldType) {
        String signature = getClassName() + "->" + fieldName + ":" + fieldType;
        int hash = signature.hashCode();
        if (log.isDebugEnabled()) {
            log.debug("getStaticFieldID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (vm.jni == null || vm.jni.acceptField(this, signature, true)) {
            if (!staticFieldMap.containsKey(hash)) {
                staticFieldMap.put(hash, new DvmField(this, fieldName, fieldType, true));
            }
            return hash;
        } else {
            return 0;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DvmClass dvmClass = (DvmClass) o;
        return Objects.equals(getClassName(), dvmClass.getClassName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClassName());
    }

    @Override
    public String toString() {
        return "class " + getClassName();
    }

    final Map<String, UnidbgPointer> nativesMap = new HashMap<>();

    UnidbgPointer findNativeFunction(Emulator<?> emulator, String method) {
        UnidbgPointer fnPtr = nativesMap.get(method);
        int index = method.indexOf('(');
        if (fnPtr == null && index != -1) {
            String symbolName = "Java_" + getClassName().replace("_", "_1").replace('/', '_') + "_" + method.substring(0, index);
            for (Module module : emulator.getMemory().getLoadedModules()) {
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    fnPtr = (UnidbgPointer) symbol.createPointer(emulator);
                    break;
                }
            }
        }
        if (fnPtr == null) {
            throw new IllegalArgumentException("find method failed: " + method);
        }
        if (vm.verbose) {
            System.out.printf("Find native function %s => %s%n", "Java_" + getClassName().replace('/', '_') + "_" + method, fnPtr);
        }
        return fnPtr;
    }

    public void callStaticJniMethod(Emulator<?> emulator, String method, Object...args) {
        try {
            callJniMethod(emulator, vm, this, this, method, args);
        } finally {
            vm.deleteLocalRefs();
        }
    }

    @SuppressWarnings("unused")
    public boolean callStaticJniMethodBoolean(Emulator<?> emulator, String method, Object...args) {
        return callStaticJniMethodInt(emulator, method, args) == VM.JNI_TRUE;
    }

    @SuppressWarnings("unused")
    public int callStaticJniMethodInt(Emulator<?> emulator, String method, Object...args) {
        try {
            return callJniMethod(emulator, vm, this, this, method, args).intValue();
        } finally {
            vm.deleteLocalRefs();
        }
    }

    @SuppressWarnings("unused")
    public long callStaticJniMethodLong(Emulator<?> emulator, String method, Object...args) {
        try {
            return callJniMethod(emulator, vm, this, this, method, args).longValue();
        } finally {
            vm.deleteLocalRefs();
        }
    }

    @SuppressWarnings("unused")
    public <T extends DvmObject<?>> T callStaticJniMethodObject(Emulator<?> emulator, String method, Object...args) {
        try {
            Number number = callJniMethod(emulator, vm, this, this, method, args);
            return vm.getObject(number.intValue());
        } finally {
            vm.deleteLocalRefs();
        }
    }

    final boolean isInstance(DvmClass dvmClass) {
        if (dvmClass == this) {
            return true;
        }

        if (superClass != null && dvmClass == superClass) {
            return true;
        }
        for (DvmClass dc : interfaceClasses) {
            if (dc == dvmClass) {
                return true;
            }
        }
        return false;
    }

    private JniFunction jni;

    protected final void setJni(JniFunction jni) {
        this.jni = jni;
    }

    final Jni getJni() {
        return jni;
    }

}
