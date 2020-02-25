package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.pointer.UnicornPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.*;

public class DvmClass extends DvmObject<String> implements Hashable {

    private static final Log log = LogFactory.getLog(DvmClass.class);

    public final BaseVM vm;
    private final DvmClass[] interfaceClasses;

    DvmClass(BaseVM vm, String className, DvmClass[] interfaceClasses) {
        super("java/lang/Class".equals(className) ? null : vm.resolveClass("java/lang/Class"), className);
        this.vm = vm;
        this.interfaceClasses = interfaceClasses;
    }

    public String getClassName() {
        return value;
    }

    public String getName() {
        return value.replace('/', '.');
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
        return vm.jni.allocObject(vm, this, signature);
    }

    private final Map<Long, DvmMethod> staticMethodMap = new HashMap<>();

    final DvmMethod getStaticMethod(long hash) {
        DvmMethod method = staticMethodMap.get(hash);
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
        long hash = signature.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getStaticMethodID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (vm.jni.acceptMethod(signature, true)) {
            staticMethodMap.put(hash, new DvmMethod(this, methodName, args, true));
            return (int) hash;
        } else {
            return 0;
        }
    }

    private final Map<Long, DvmMethod> methodMap = new HashMap<>();

    final DvmMethod getMethod(long hash) {
        DvmMethod method = methodMap.get(hash);
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
        long hash = signature.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getMethodID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (vm.jni.acceptMethod(signature, false)) {
            methodMap.put(hash, new DvmMethod(this, methodName, args, false));
            return (int) hash;
        } else {
            return 0;
        }
    }

    private final Map<Long, DvmField> fieldMap = new HashMap<>();

    final DvmField getField(long hash) {
        DvmField field = fieldMap.get(hash);
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
        long hash = signature.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getFieldID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (vm.jni != null && vm.jni.acceptField(signature, false)) {
            fieldMap.put(hash, new DvmField(this, fieldName, fieldType));
            return (int) hash;
        } else {
            return 0;
        }
    }

    private final Map<Long, DvmField> staticFieldMap = new HashMap<>();

    final DvmField getStaticField(long hash) {
        DvmField field = staticFieldMap.get(hash);
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
        long hash = signature.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getStaticFieldID signature=" + signature + ", hash=0x" + Long.toHexString(hash));
        }
        if (vm.jni.acceptField(signature, true)) {
            staticFieldMap.put(hash, new DvmField(this, fieldName, fieldType));
            return (int) hash;
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

    final Map<String, UnicornPointer> nativesMap = new HashMap<>();

    UnicornPointer findNativeFunction(Emulator<?> emulator, String method) {
        UnicornPointer fnPtr = nativesMap.get(method);
        int index = method.indexOf('(');
        if (fnPtr == null && index != -1) {
            String symbolName = "Java_" + getClassName().replace('/', '_') + "_" + method.substring(0, index);
            for (Module module : emulator.getMemory().getLoadedModules()) {
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol != null) {
                    fnPtr = (UnicornPointer) symbol.createPointer(emulator);
                    break;
                }
            }
        }
        if (fnPtr == null) {
            throw new IllegalArgumentException("find method failed: " + method);
        }
        if (vm.verbose) {
            System.out.println(String.format("Find native function %s => %s", "Java_" + getClassName().replace('/', '_') + "_" + method, fnPtr));
        }
        return fnPtr;
    }

    public Number callStaticJniMethod(Emulator<?> emulator, String method, Object...args) {
        UnicornPointer fnPtr = findNativeFunction(emulator, method);
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(this.hashCode());
        if (args != null) {
            for (Object arg : args) {
                list.add(arg);

                if(arg instanceof DvmObject) {
                    vm.addLocalObject((DvmObject<?>) arg);
                }
            }
        }
        return LinuxModule.emulateFunction(emulator, fnPtr.peer, list.toArray())[0];
    }

}
