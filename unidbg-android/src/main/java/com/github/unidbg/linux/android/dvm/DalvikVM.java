package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ArmHook;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.dvm.apk.Apk;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.array.CharArray;
import com.github.unidbg.linux.android.dvm.array.DoubleArray;
import com.github.unidbg.linux.android.dvm.array.FloatArray;
import com.github.unidbg.linux.android.dvm.array.IntArray;
import com.github.unidbg.linux.android.dvm.array.PrimitiveArray;
import com.github.unidbg.linux.android.dvm.array.ShortArray;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

public class DalvikVM extends BaseVM implements VM {

    private static final Logger log = LoggerFactory.getLogger(DalvikVM.class);

    private final UnidbgPointer _JavaVM;
    private final UnidbgPointer _JNIEnv;

    public DalvikVM(AndroidEmulator emulator, File apkFile) {
        super(emulator, apkFile);

        final SvcMemory svcMemory = emulator.getSvcMemory();
        _JavaVM = svcMemory.allocate(emulator.getPointerSize(), "_JavaVM");

        Pointer _GetVersion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return JNI_VERSION_1_6;
            }
        });

        Pointer _DefineClass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _FindClass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer env = context.getPointerArg(0);
                Pointer className = context.getPointerArg(1);
                String name = className.getString(0);

                boolean notFound = notFoundClassSet.contains(name);
                if (verbose) {
                    if (notFound) {
                        System.out.printf("JNIEnv->FindNoClass(%s) was called from %s%n", name, context.getLRPointer());
                    } else {
                        System.out.printf("JNIEnv->FindClass(%s) was called from %s%n", name, context.getLRPointer());
                    }
                }

                if (notFound) {
                    throwable = resolveClass("java/lang/NoClassDefFoundError").newObject(name);
                    return 0;
                }

                DvmClass dvmClass = resolveClass(name);
                long hash = dvmClass.hashCode() & 0xffffffffL;
                if (log.isDebugEnabled()) {
                    log.debug("FindClass env={}, className={}, hash=0x{}", env, name, Long.toHexString(hash));
                }
                return hash;
            }
        });

        Pointer _FromReflectedMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _FromReflectedField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ToReflectedMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = null;
                if (dvmClass != null) {
                    dvmMethod = dvmClass.getStaticMethod(jmethodID.toIntPeer());
                    if (dvmMethod == null) {
                        dvmMethod = dvmClass.getMethod(jmethodID.toIntPeer());
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("ToReflectedMethod clazz={}, jmethodID={}, lr={}", dvmClass, jmethodID, context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->ToReflectedMethod(%s, %s, %s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, dvmMethod.isStatic ? "is static" : "not static", context.getLRPointer());
                    }

                    return addLocalObject(dvmMethod.toReflectedMethod());
                }
            }
        });
        
        Pointer _GetSuperclass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetSuperClass(%s) was called from %s%n", dvmClass, context.getLRPointer());
                }
                if (dvmClass.getClassName().equals("java/lang/Object")) {
                    if (log.isDebugEnabled()) {
                        log.debug("JNIEnv->GetSuperClass(class=Object) returns NULL per JNI spec.");
                    }
                    return 0;
                }
                DvmClass superClass = dvmClass.getSuperclass();
                if (superClass == null) {
                    // 未声明父类: 按 ART 语义回落 java/lang/Object, 不再抛异常中断模拟
                    if (log.isDebugEnabled()) {
                        log.debug("JNIEnv->GetSuperClass was called, class = {}, superClass undeclared, fallback to java/lang/Object.", dvmClass.getClassName());
                    }
                    return resolveClass("java/lang/Object").hashCode();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("JNIEnv->GetSuperClass was called, class = {}, superClass = {}", dvmClass.getClassName(), superClass.getClassName());
                    }
                    return superClass.hashCode();
                }
            }
        });

        Pointer _IsAssignableFrom = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ToReflectedField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _Throw = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                log.warn("Throw dvmObject={}, class={}", dvmObject, dvmObject != null ? dvmObject.getObjectType() : null);
                throwable = dvmObject;
                return 0;
            }
        });

        Pointer _ThrowNew = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ExceptionOccurred = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                long exception = throwable == null ? JNI_NULL : (throwable.hashCode() & 0xffffffffL);
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionOccurred: 0x{}", Long.toHexString(exception));
                }
                return exception;
            }
        });

        Pointer _ExceptionDescribe = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ExceptionClear = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionClear");
                }
                throwable = null;
                return 0;
            }
        });

        Pointer _FatalError = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _PushLocalFrame = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int capacity = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("PushLocalFrame capacity={}", capacity);
                }
                return JNI_OK;
            }
        });

        Pointer _PopLocalFrame = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer jresult = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("PopLocalFrame jresult={}", jresult);
                }
                return jresult == null ? 0 : jresult.toIntPeer();
            }
        });

        Pointer _NewGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewGlobalRef object={}, dvmObject={}", object, dvmObject);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewGlobalRef(%s) was called from %s%n", dvmObject, context.getLRPointer());
                }
                return addGlobalObject(dvmObject);
            }
        });

        Pointer _DeleteGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteGlobalRef object={}", object);
                }
                ObjRef ref = object == null ? null : globalObjectMap.get(object.toIntPeer());
                if (ref != null) {
                    ref.refCount--;
                    if (ref.refCount <= 0) {
                        globalObjectMap.remove(object.toIntPeer());
                        ref.obj.onDeleteRef();
                    }
                }
                if (verbose) {
                    System.out.printf("JNIEnv->DeleteGlobalRef(%s) was called from %s%n", ref == null ? object : ref, context.getLRPointer());
                }
                return 0;
            }
        });

        Pointer _DeleteLocalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteLocalRef object={}", object);
                }
                return 0;
            }
        });

        Pointer _IsSameObject = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer ref1 = context.getPointerArg(1);
                UnidbgPointer ref2 = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("IsSameObject ref1={}, ref2={}, LR={}", ref1, ref2, context.getLRPointer());
                }
                return ref1 == ref2 || ref1.equals(ref2) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _NewLocalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewLocalRef object={}, dvmObject={}, class={}", object, dvmObject, dvmObject != null ? dvmObject.getObjectType() : null);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewLocalRef(%s) was called from %s%n", dvmObject, context.getLRPointer());
                }
                return object.toIntPeer();
            }
        });

        Pointer _EnsureLocalCapacity = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int capacity = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("EnsureLocalCapacity capacity={}", capacity);
                }
                return 0;
            }
        });

        Pointer _AllocObject = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("AllocObject clazz={}, lr={}", dvmClass, context.getLRPointer());
                }
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmClass.allocObject();
                    if (verbose) {
                        System.out.printf("JNIEnv->AllocObject(%s => %s) was called from %s%n", dvmClass.getClassName(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _NewObject = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObject clazz={}, jmethodID={}, lr={}", dvmClass, jmethodID, context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    DvmObject<?> obj = dvmMethod.newObject(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->NewObject(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _NewObjectV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz={}, jmethodID={}, va_list={}, lr={}", dvmClass, jmethodID, va_list, context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.newObjectV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->NewObjectV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _NewObjectA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectA clazz={}, jmethodID={}, jvalue={}, lr={}", dvmClass, jmethodID, jvalue, context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    DvmObject<?> obj = dvmMethod.newObjectA(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->NewObjectA(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetObjectClass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> dvmObject = object == null ? null : getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectClass object={}, dvmObject={}", object, dvmObject);
                }
                if (dvmObject == null) {
                    throw new BackendException();
                } else {
                    DvmClass dvmClass = dvmObject.getObjectType();
                    return dvmClass.hashCode();
                }
            }
        });

        Pointer _IsInstanceOf = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("IsInstanceOf object={}, clazz={}, dvmObject={}, dvmClass={}", object, clazz, dvmObject, dvmClass);
                }
                if (dvmObject == null || dvmClass == null) {
                    throw new BackendException();
                }
                boolean flag = dvmObject.isInstanceOf(dvmClass);
                return flag ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _GetMethodID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                Pointer methodName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetMethodID class={}, methodName={}, args={}, LR={}", clazz, name, args, context.getLRPointer());
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getMethodID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetMethodID(%s.%s%s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _CallObjectMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethod object={}, jmethodID={}", object, jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    DvmObject<?> ret = dvmMethod.callObjectMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethod(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return addLocalObject(ret);
                }
            }
        });

        Pointer _CallObjectMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodV object={}, jmethodID={}, va_list={}, lr={}", object, jmethodID, va_list, context.getLRPointer());
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass + ", jmethodID=" + jmethodID);
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callObjectMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallObjectMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodA object={}, jmethodID={}, jvalue={}, lr={}", object, jmethodID, jvalue, context.getLRPointer());
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass + ", jmethodID=" + jmethodID);
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callObjectMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethodA(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallBooleanMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethod object={}, jmethodID={}", object, jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    boolean ret = dvmMethod.callBooleanMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethod(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallBooleanMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    boolean ret = dvmMethod.callBooleanMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallBooleanMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodA object={}, jmethodID={}, jvalue={}", object, jmethodID, jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    boolean ret = dvmMethod.callBooleanMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethodA(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallByteMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallByteMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallByteMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    byte ret = dvmMethod.callByteMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallByteMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallByteMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallCharMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallCharMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallCharMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    char ret = dvmMethod.callCharMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallCharMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallCharMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallShortMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallShortMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallShortMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    short ret = dvmMethod.callShortMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallShortMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallShortMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallIntMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethod object={}, jmethodID={}", object, jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    int ret = dvmMethod.callIntMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethod(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallIntMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    int ret = dvmMethod.callIntMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallIntMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodA object={}, jmethodID={}, jvalue={}", object, jmethodID, jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    int ret = dvmMethod.callIntMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethodA(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallLongMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallLongMethod object={}, jmethodID={}", object, jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    long ret = dvmMethod.callLongMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallLongMethod(%s, %s(%s) => 0x%xL) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    context.setR1((int) (ret >> 32));
                    return (ret & 0xffffffffL);
                }
            }
        });

        Pointer _CallLongMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallLongMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    long ret = dvmMethod.callLongMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallLongMethodV(%s, %s(%s) => 0x%xL) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    context.setR1((int) (ret >> 32));
                    return (ret & 0xffffffffL);
                }
            }
        });

        Pointer _CallLongMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallFloatMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallFloatMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallFloatMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    float ret = dvmMethod.callFloatMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallFloatMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(4);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    buffer.flip();
                    return (buffer.getInt() & 0xffffffffL);
                }
            }
        });

        Pointer _CallFloatMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallDoubleMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallDoubleMethod object={}, jmethodID={}", object, jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    double ret = dvmMethod.callDoubleMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallDoubleMethod(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(4);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat((float) ret);
                    buffer.flip();
                    return (buffer.getInt() & 0xffffffffL);
                }
            }
        });

        Pointer _CallDoubleMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallDoubleMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallVoidMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethod object={}, jmethodID={}", object, jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    dvmMethod.callVoidMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethod(%s, %s(%s)) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallVoidMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethodV object={}, jmethodID={}, va_list={}", object, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    dvmMethod.callVoidMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethodV(%s, %s(%s)) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallVoidMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethodA object={}, jmethodID={}, jvalue={}", object, jmethodID, jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    dvmMethod.callVoidMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethodA(%s, %s(%s)) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallNonvirtualObjectMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualObjectMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualObjectMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualBooleanMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualBooleanMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualBooleanMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                UnidbgPointer jmethodID = context.getPointerArg(3);
                UnidbgPointer jvalue = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("CallNonvirtualBooleanMethodA object={}, clazz={}, jmethodID={}, jvalue={}", object, clazz, jmethodID, jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    if (dvmMethod.isConstructor()) {
                        throw new IllegalStateException();
                    }
                    boolean ret = dvmMethod.callBooleanMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallNonvirtualBooleanMethodA(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallNonvirtualByteMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualByteMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualByteMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualCharMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualCharMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualCharMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualShortMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualShortMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualShortMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualIntMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualIntMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualIntMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualLongMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualLongMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualLongMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualFloatMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualFloatMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualFloatMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualDoubleMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualDoubleMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualDoubleMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualVoidMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualVoidMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                UnidbgPointer jmethodID = context.getPointerArg(3);
                UnidbgPointer va_list = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("CallNonvirtualVoidMethodV object={}, clazz={}, jmethodID={}, va_list={}", object, clazz, jmethodID, va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    if (dvmMethod.isConstructor()) {
                        DvmObject<?> obj = dvmMethod.newObjectV(vaList);
                        Objects.requireNonNull(dvmObject).setValue(obj.value);
                    } else {
                        dvmMethod.callVoidMethodV(dvmObject, vaList);
                    }
                    if (verbose) {
                        System.out.printf("JNIEnv->CallNonvirtualVoidMethodV(%s, %s, %s(%s)) was called from %s%n", dvmObject, dvmClass.getClassName(), dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallNonVirtualVoidMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                UnidbgPointer jmethodID = context.getPointerArg(3);
                UnidbgPointer jvalue = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("CallNonVirtualVoidMethodA object={}, clazz={}, jmethodID={}, jvalue={}", object, clazz, jmethodID, jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    if (dvmMethod.isConstructor()) {
                        DvmObject<?> obj = dvmMethod.newObjectV(vaList);
                        Objects.requireNonNull(dvmObject).setValue(obj.value);
                    } else {
                        dvmMethod.callVoidMethodA(dvmObject, vaList);
                    }
                    if (verbose) {
                        System.out.printf("JNIEnv->CallNonVirtualVoidMethodA(%s, %s, %s(%s)) was called from %s%n", dvmObject, dvmClass.getClassName(), dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _GetFieldID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer fieldName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetFieldID class={}, fieldName={}, args={}", clazz, name, args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getFieldID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetFieldID(%s.%s %s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _GetObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectField object={}, jfieldID={}", object, jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmField.getObjectField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetObjectField(%s, %s %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, dvmField.fieldType, obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetBooleanField object={}, jfieldID={}", object, jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getBooleanField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetBooleanField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, ret == JNI_TRUE, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetByteField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetCharField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetShortField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntField object={}, jfieldID={}", object, jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getIntField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetIntField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetLongField object={}, jfieldID={}", object, jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    long ret = dvmField.getLongField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetLongField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    context.setR1((int) (ret >> 32));
                    return ret;
                }
            }
        });

        Pointer _GetFloatField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetFloatField object={}, jfieldID={}", object, jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    float ret = dvmField.getFloatField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetFloatField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(4);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    buffer.flip();
                    return (buffer.getInt() & 0xffffffffL);
                }
            }
        });

        Pointer _GetDoubleField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                UnidbgPointer value = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetObjectField object={}, jfieldID={}, value={}", object, jfieldID, value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = value == null ? null : getObject(value.toIntPeer());
                    dvmField.setObjectField(dvmObject, obj);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetObjectField(%s, %s %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, dvmField.fieldType, obj, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                int value = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetBooleanField object={}, jfieldID={}, value={}", object, jfieldID, value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    boolean flag = BaseVM.valueOf(value);
                    dvmField.setBooleanField(dvmObject, flag);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetBooleanField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, flag, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetByteField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetCharField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetShortField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                int value = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntField object={}, jfieldID={}, value={}", object, jfieldID, value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setIntField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetIntField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });
        
        Pointer _SetLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                UnidbgPointer sp = context.getStackPointer();
                long value = sp.getLong(0);
                if (log.isDebugEnabled()) {
                    log.debug("SetLongField object={}, jfieldID={}, value={}", object, jfieldID, value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setLongField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetLongField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetFloatField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(4);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt(context.getIntArg(3));
                buffer.flip();
                float value = buffer.getFloat();
                if (log.isDebugEnabled()) {
                    log.debug("SetFloatField object={}, jfieldID={}, value={}", object, jfieldID, value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setFloatField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetFloatField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });
        
        Pointer _SetDoubleField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                UnidbgPointer sp = context.getStackPointer();
                double value = sp.getDouble(0);
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleField object={}, jfieldID={}, value={}", object, jfieldID, value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setDoubleField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetDoubleField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _GetStaticMethodID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                Pointer methodName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticMethodID class={}, methodName={}, args={}, LR={}", clazz, name, args, context.getLRPointer());
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getStaticMethodID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetStaticMethodID(%s.%s%s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _CallStaticObjectMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethod clazz={}, jmethodID={}", clazz, jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callStaticObjectMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallStaticBooleanMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodA clazz={}, jmethodID={}, jvalue={}", clazz, jmethodID, jvalue);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    boolean ret = dvmMethod.callStaticBooleanMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethodA(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? VM.JNI_TRUE : VM.JNI_FALSE;
                }
            }
        });

        Pointer _CallStaticObjectMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodV clazz={}, jmethodID={}, va_list={}", clazz, jmethodID, va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callStaticObjectMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethodV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallStaticObjectMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodA clazz={}, jmethodID={}, jvalue={}", clazz, jmethodID, jvalue);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callStaticObjectMethodA(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethodA(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallStaticBooleanMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethod clazz={}, jmethodID={}", clazz, jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    boolean ret = dvmMethod.CallStaticBooleanMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallStaticBooleanMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodV clazz={}, jmethodID={}, va_list={}", clazz, jmethodID, va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    boolean ret = dvmMethod.callStaticBooleanMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethodV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallStaticByteMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticByteMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticByteMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticCharMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticCharMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticCharMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticShortMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticShortMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticShortMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticIntMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz={}, jmethodID={}", clazz, jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    int ret = dvmMethod.callStaticIntMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticIntMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallStaticIntMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz={}, jmethodID={}, va_list={}", clazz, jmethodID, va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    int ret = dvmMethod.callStaticIntMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticIntMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallStaticIntMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticLongMethod = svcMemory.registerSvc(new ArmHook() {
            @Override
            protected HookStatus hook(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethod clazz={}, jmethodID={}", clazz, jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    long value = dvmMethod.callStaticLongMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticLongMethod(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), context.getLRPointer());
                    }
                    context.setR1((int) (value >> 32));
                    return HookStatus.LR(emulator, value & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticLongMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethodV clazz={}, jmethodID={}, va_list={}, lr={}", clazz, jmethodID, va_list, context.getLRPointer());
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    long ret = dvmMethod.callStaticLongMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticLongMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    context.setR1((int) (ret >> 32));
                    return (ret & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticLongMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticFloatMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticFloatMethod clazz={}, jmethodID={}", clazz, jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    float ret = dvmMethod.callStaticFloatMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticFloatMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(4);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    buffer.flip();
                    return (buffer.getInt() & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticFloatMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticFloatMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticDoubleMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticDoubleMethod clazz={}, jmethodID={}", clazz, jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    double ret = dvmMethod.callStaticDoubleMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticDoubleMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(8);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putDouble(ret);
                    buffer.flip();
                    int i1 = buffer.getInt();
                    int i2 = buffer.getInt();
                    context.setR1(i2);
                    return i1;
                }
            }
        });

        Pointer _CallStaticDoubleMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticDoubleMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticVoidMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethod clazz={}, jmethodID={}", clazz, jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM.this, dvmMethod);
                    dvmMethod.callStaticVoidMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethod(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallStaticVoidMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodV clazz={}, jmethodID={}, va_list={}", clazz, jmethodID, va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList32(emulator, DalvikVM.this, va_list, dvmMethod);
                    dvmMethod.callStaticVoidMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethodV(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallStaticVoidMethodA = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodA clazz={}, jmethodID={}, jvalue={}", clazz, jmethodID, jvalue);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM.this, jvalue, dvmMethod);
                    dvmMethod.callStaticVoidMethodA(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethodA(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _GetStaticFieldID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer fieldName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticFieldID class={}, fieldName={}, args={}", clazz, name, args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getStaticFieldID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetStaticFieldID(%s.%s%s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _GetStaticObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticObjectField clazz={}, jfieldID={}", clazz, jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmField.getStaticObjectField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticObjectField(%s, %s %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, dvmField.fieldType, obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetStaticBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticBooleanField clazz={}, jfieldID={}", clazz, jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    boolean ret = dvmField.getStaticBooleanField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticBooleanField(%s, %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret ? VM.JNI_TRUE : VM.JNI_FALSE;
                }
            }
        });

        Pointer _GetStaticByteField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticByteField clazz={}, jfieldID={}", clazz, jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    byte ret = dvmField.getStaticByteField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticByteField(%s, %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetStaticCharField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetStaticShortField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetStaticIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticIntField clazz={}, jfieldID={}", clazz, jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getStaticIntField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticIntField(%s, %s => 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetStaticLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticLongField clazz={}, jfieldID={}", clazz, jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    long ret = dvmField.getStaticLongField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticLongField(%s, %s => 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    context.setR1((int) (ret >> 32));
                    return ret;
                }
            }
        });

        Pointer _GetStaticFloatField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetStaticDoubleField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                UnidbgPointer value = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticObjectField clazz={}, jfieldID={}, value={}", clazz, jfieldID, value);
                }
                DvmObject<?> dvmObject = value == null ? null : getObject(value.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    dvmField.setStaticObjectField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticObjectField(%s, %s, %s) was called from %s%n", dvmClass, dvmField.fieldName, dvmObject, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetStaticBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                int value = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticBooleanField clazz={}, jfieldID={}, value={}", clazz, jfieldID, value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    boolean flag = BaseVM.valueOf(value);
                    dvmField.setStaticBooleanField(flag);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticBooleanField(%s, %s, %s) was called from %s%n", dvmClass, dvmField.fieldName, flag, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetStaticByteField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticCharField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticShortField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                int value = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticIntField clazz={}, jfieldID={}, value={}", clazz, jfieldID, value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    dvmField.setStaticIntField(value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticIntField(%s, %s, 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetStaticLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                UnidbgPointer sp = context.getStackPointer();
                long value = sp.getLong(0);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticLongField clazz={}, jfieldID={}, value={}", clazz, jfieldID, value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    dvmField.setStaticLongField(value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticLongField(%s, %s, 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetStaticFloatField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(4);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt(context.getIntArg(3));
                buffer.flip();
                float value = buffer.getFloat();
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticFloatField clazz={}, jfieldID={}, value={}", clazz, jfieldID, value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    dvmField.setStaticFloatField(value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticFloatField(%s, %s, %s) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetStaticDoubleField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                UnidbgPointer sp = context.getStackPointer();
                double value = sp.getDouble(0);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticDoubleField clazz={}, jfieldID={}, value={}", clazz, jfieldID, value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    dvmField.setStaticDoubleField(value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticDoubleField(%s, %s, %s) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _GetStringUTFLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> string = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFLength string={}, lr={}", string, context.getLRPointer());
                }
                String value = (String) Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUTFLength(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                return data.length;
            }
        });

        Pointer _GetStringUTFChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUtfChars(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string={}, isCopy={}, value={}, lr={}", string, isCopy, value, context.getLRPointer());
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                UnidbgPointer pointer = string.allocateMemoryBlock(emulator, data.length);
                pointer.write(0, data, 0, data.length);
                return pointer.toIntPeer();
            }
        });

        Pointer _ReleaseStringUTFChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->ReleaseStringUTFChars(%s) was called from %s%n", string, context.getLRPointer());
                }
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringUTFChars string={}, pointer={}, lr={}", string, pointer, context.getLRPointer());
                }
                Objects.requireNonNull(string).freeMemoryBlock(pointer);
                return 0;
            }
        });

        Pointer _GetArrayLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer pointer = context.getPointerArg(1);
                Array<?> array = Objects.requireNonNull((Array<?>) getObject(pointer.toIntPeer()));
                if (log.isDebugEnabled()) {
                    log.debug("GetArrayLength array={}, lr={}", array, context.getLRPointer());
                }
                if (verbose) {
                    System.out.printf("JNIEnv->GetArrayLength(%s => %s) was called from %s%n", array, array.length(), context.getLRPointer());
                }
                return array.length();
            }
        });

        Pointer _NewObjectArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                UnidbgPointer elementClass = context.getPointerArg(2);
                UnidbgPointer initialElement = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectArray size={}, elementClass={}, initialElement={}", size, elementClass, initialElement);
                }
                DvmClass dvmClass = classMap.get(elementClass.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException("elementClass=" + elementClass);
                }

                DvmObject<?> obj = size == 0 ? null : initialElement == null ? null : getObject(initialElement.toIntPeer());
                DvmObject<?>[] array = new DvmObject[size];
                Arrays.fill(array, obj);

                return addLocalObject(ArrayObject.newObjectArray(dvmClass, array));
            }
        });

        Pointer _GetObjectArrayElement = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int index = context.getIntArg(2);
                ArrayObject array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectArrayElement array={}, index={}", array, index);
                }
                DvmObject<?> obj = Objects.requireNonNull(array).getValue()[index];
                if (verbose) {
                    System.out.printf("JNIEnv->GetObjectArrayElement(%s, %d) => %s was called from %s%n", array, index, obj, context.getLRPointer());
                }
                return addLocalObject(obj);
            }
        });

        Pointer _SetObjectArrayElement = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int index = context.getIntArg(2);
                UnidbgPointer element = context.getPointerArg(3);
                ArrayObject array = getObject(object.toIntPeer());
                DvmObject<?> obj = element == null ? null : getObject(element.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("setObjectArrayElement array={}, index={}, obj={}", array, index, obj);
                }
                DvmObject<?>[] objs = Objects.requireNonNull(array).getValue();
                objs[index] = obj;
                return 0;
            }
        });

        Pointer _NewLongArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewFloatArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("NewFloatArray size={}", size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewFloatArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new FloatArray(DalvikVM.this, new float[size]));
            }
        });

        Pointer _GetLongArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetFloatArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                FloatArray array = getObject(object.toIntPeer());
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).toIntPeer();
            }
        });

        Pointer _GetDoubleArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewBooleanArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });
        
        Pointer _NewByteArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("NewByteArray size={}, LR={}, PC={}", size, context.getLRPointer(), context.getPCPointer());
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewByteArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new ByteArray(DalvikVM.this, new byte[size]));
            }
        });

        Pointer _NewCharArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("NewCharArray size={}, LR={}, PC={}", size, context.getLRPointer(), context.getPCPointer());
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewCharArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new CharArray(DalvikVM.this, new char[size]));
            }
        });

        Pointer _NewShortArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewIntArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("NewIntArray size={}", size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewIntArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new IntArray(DalvikVM.this, new int[size]));
            }
        });
        
        Pointer _NewDoubleArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("_NewDoubleArray size={}", size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewDoubleArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new DoubleArray(DalvikVM.this, new double[size]));
            }
        });

        Pointer _GetBooleanArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetByteArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                ByteArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    Inspector.inspect(array != null ? array.value : null, "GetByteArrayElements array=" + array + ", isCopy=" + isCopy);
                }
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).toIntPeer();
            }
        });

        Pointer _GetCharArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                CharArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetCharArrayElements array={}, isCopy={}", array, isCopy);
                }
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).toIntPeer();
            }
        });

        Pointer _GetShortArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetIntArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                IntArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetIntArrayElements array={}, isCopy={}", array, isCopy);
                }
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).toIntPeer();
            }
        });

        Pointer _NewString = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer unicodeChars = context.getPointerArg(1);
                int len = context.getIntArg(2);
                if (unicodeChars == null) {
                    if (len == 0) {
                        return VM.JNI_NULL;
                    }
                    throw new IllegalStateException("unicodeChars is null");
                }
                ByteBuffer buffer = ByteBuffer.wrap(unicodeChars.getByteArray(0, len * 2));
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                StringBuilder builder = new StringBuilder(len);
                for (int i = 0; i < len; i++) {
                    builder.append(buffer.getChar());
                }
                String string = builder.toString();
                if (log.isDebugEnabled()) {
                    log.debug("NewString unicodeChars={}, len={}, string={}", unicodeChars, len, string);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewString(\"%s\") was called from %s%n", string, context.getLRPointer());
                }
                return addLocalObject(new StringObject(DalvikVM.this, string));
            }
        });

        Pointer _GetStringLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> string = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringLength string={}, lr={}", string, context.getLRPointer());
                }
                String value = (String) Objects.requireNonNull(string).getValue();
                return value.length();
            }
        });

        Pointer _GetStringChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = Objects.requireNonNull(string).getValue();
                byte[] bytes = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringChars string={}, isCopy={}, value={}, lr={}", string, isCopy, value, context.getLRPointer());
                }
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUTFChars(\"%s\") was called from %s%n", value, context.getLRPointer());
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                UnidbgPointer pointer = string.allocateMemoryBlock(emulator, data.length);
                pointer.write(0, data, 0, data.length);
                return pointer.toIntPeer();
            }
        });

        Pointer _ReleaseStringChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringChars string={}, pointer={}, lr={}", string, pointer, context.getLRPointer());
                }
                Objects.requireNonNull(string).freeMemoryBlock(pointer);
                return 0;
            }
        });

        Pointer _NewStringUTF = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer bytes = context.getPointerArg(1);
                if (bytes == null) {
                    return VM.JNI_NULL;
                }

                String string = bytes.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("NewStringUTF bytes={}, string={}", bytes, string);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewStringUTF(\"%s\") was called from %s%n", string, context.getLRPointer());
                }
                return addLocalObject(new StringObject(DalvikVM.this, string));
            }
        });

        Pointer _ReleaseBooleanArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseByteArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                ByteArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements array={}, pointer={}, mode={}", array, pointer, mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseCharArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                CharArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseCharArrayElements array={}, pointer={}, mode={}", array, pointer, mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseShortArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseIntArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                IntArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseIntArrayElements array={}, pointer={}, mode={}", array, pointer, mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseLongArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseFloatArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                FloatArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseFloatArrayElements array={}, pointer={}, mode={}", array, pointer, mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseDoubleArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetBooleanArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetByteArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                ByteArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetByteArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                byte[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "GetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _GetCharArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                CharArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetCharArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                char[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                for (int i = 0; i < data.length; i++) {
                    buf.setShort((long) i * 2, (short) data[i]);
                }
                return 0;
            }
        });

        Pointer _GetShortArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                ShortArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetShortArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                short[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                if (log.isDebugEnabled()) {
                    log.debug("GetShortArrayRegion array={}, start={}, length={}, buf={}", array, start, length, buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _GetIntArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetLongArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetFloatArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                FloatArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetFloatArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                float[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                if (log.isDebugEnabled()) {
                    log.debug("GetFloatArrayRegion array={}, start={}, length={}, buf={}", array, start, length, buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _GetDoubleArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                DoubleArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetDoubleArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                double[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                if (log.isDebugEnabled()) {
                    log.debug("GetDoubleArrayRegion array={}, start={}, length={}, buf={}", array, start, length, buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _SetBooleanArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetByteArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                ByteArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->SetByteArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                byte[] data = buf.getByteArray(0, length);
                if (log.isDebugEnabled()) {
                    if (data.length > 1024) {
                        Inspector.inspect(Arrays.copyOf(data, 1024), "SetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                    } else {
                        Inspector.inspect(data, "SetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                    }
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _SetCharArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                CharArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->SetCharArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                char[] data = new char[length];
                for (int i = 0; i < length; i++) {
                    data[i] = (char) buf.getShort((long) i * 2);
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _SetShortArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });
        
        Pointer _SetIntArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                IntArray array = getObject(object.toIntPeer());
                int[] data = buf.getIntArray(0, length);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array={}, start={}, length={}, buf={}", array, start, length, buf);
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _SetLongArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetFloatArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                FloatArray array = getObject(object.toIntPeer());
                float[] data = buf.getFloatArray(0, length);
                if (log.isDebugEnabled()) {
                    log.debug("SetFloatArrayRegion array={}, start={}, length={}, buf={}", array, start, length, buf);
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });
        
        Pointer _SetDoubleArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                DoubleArray array = getObject(object.toIntPeer());
                double[] data = buf.getDoubleArray(0, length);
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleArrayRegion array={}, start={}, length={}, buf={}", array, start, length, buf);
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _RegisterNatives = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                Pointer methods = context.getPointerArg(2);
                int nMethods = context.getIntArg(3);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("RegisterNatives dvmClass={}, methods={}, nMethods={}", dvmClass, methods, nMethods);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->RegisterNatives(%s, %s, %d) was called from %s%n", dvmClass.getClassName(), methods, nMethods, context.getLRPointer());
                }
                for (int i = 0; i < nMethods; i++) {
                    Pointer method = methods.share(i * 0xcL);
                    Pointer name = method.getPointer(0);
                    Pointer signature = method.getPointer(4);
                    Pointer fnPtr = method.getPointer(8);
                    String methodName = name.getString(0);
                    String signatureValue = signature.getString(0);
                    if (log.isDebugEnabled()) {
                        log.debug("RegisterNatives dvmClass={}, name={}, signature={}, fnPtr={}", dvmClass, methodName, signatureValue, fnPtr);
                    }
                    dvmClass.nativesMap.put(methodName + signatureValue, (UnidbgPointer) fnPtr);

                    if (verbose) {
                        System.out.printf("RegisterNative(%s, %s%s, %s)%n", dvmClass.getClassName(), methodName, signatureValue, fnPtr);
                    }
                }
                return JNI_OK;
            }
        });

        Pointer _UnregisterNatives = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _MonitorEnter = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer env = context.getPointerArg(0);
                DvmObject<?> obj = getObject(context.getPointerArg(1).toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("MonitorEnter env={}, obj={}", env, obj);
                }
                return 0;
            }
        });

        Pointer _MonitorExit = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer env = context.getPointerArg(0);
                DvmObject<?> obj = getObject(context.getPointerArg(1).toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("MonitorExit env={}, obj={}", env, obj);
                }
                return 0;
            }
        });

        Pointer _GetJavaVM = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer vm = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("GetJavaVM vm={}", vm);
                }
                vm.setPointer(0, _JavaVM);
                return JNI_OK;
            }
        });

        Pointer _GetStringRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);

                StringObject string = getObject(object.toIntPeer());
                String value = Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringRegion(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] bytes = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringRegion string={}, value={}, start={}, length={}, buf{}, lr={}", string, value, start, length, buf, context.getLRPointer());
                }
                byte[] data = Arrays.copyOfRange(bytes, start, start+length+1);
                buf.write(0, data, 0, data.length);
                return JNI_OK;
            }
        });

        Pointer _GetStringUTFRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);

                StringObject string = getObject(object.toIntPeer());
                String value = Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUTFRegion(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFRegion string={}, value={}, start={}, length={}, buf{}, lr={}", string, value, start, length, buf, context.getLRPointer());
                }
                byte[] data = Arrays.copyOfRange(bytes, start, start+length+1);
                buf.write(0, data, 0, data.length);
                return JNI_OK;
            }
        });

        Pointer _GetPrimitiveArrayCritical = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                PrimitiveArray<?> array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetPrimitiveArrayCritical array={}, isCopy={}", array, isCopy);
                }
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).toIntPeer();
            }
        });

        Pointer _ReleasePrimitiveArrayCritical = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                PrimitiveArray<?> array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleasePrimitiveArrayCritical array={}, pointer={}, mode={}", array, pointer, mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _GetStringCritical = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseStringCritical = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewWeakGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = Objects.requireNonNull(getObject(object.toIntPeer()));
                if (log.isDebugEnabled()) {
                    log.debug("NewWeakGlobalRef object={}, dvmObject={}, class={}", object, dvmObject, dvmObject.getClass());
                }
                return addObject(dvmObject, true, true);
            }
        });

        Pointer _DeleteWeakGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ExceptionCheck = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionCheck throwable={}", throwable);
                }
                return throwable == null ? JNI_FALSE : JNI_TRUE;
            }
        });

        Pointer _NewDirectByteBuffer = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetDirectBufferAddress = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetDirectBufferCapacity = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetObjectRefType = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return JNIInvalidRefType;
                }
                int hash = object.toIntPeer();
                ObjRef dvmLocalObject = localObjectMap.get(object.toIntPeer());
                ObjRef dvmGlobalObject;
                if (globalObjectMap.containsKey(hash)) {
                    dvmGlobalObject = globalObjectMap.get(hash);
                } else {
                    dvmGlobalObject = weakGlobalObjectMap.getOrDefault(hash, null);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectRefType object={}, dvmGlobalObject={}, dvmLocalObject={}, LR={}", object, dvmGlobalObject, dvmLocalObject, context.getLRPointer());
                }
                if (dvmGlobalObject != null) {
                    return dvmGlobalObject.weak ? JNIWeakGlobalRefType : JNIGlobalRefType;
                } else if(dvmLocalObject != null) {
                    return JNILocalRefType;
                } else {
                    return JNIInvalidRefType;
                }
            }
        });

        Pointer _GetModule = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        final int last = 0x3a4;
        final UnidbgPointer impl = svcMemory.allocate(last + 4, "JNIEnv.impl");
        final ByteBuffer table = ByteBuffer.allocate(last + 4).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i <= last; i += 4) {
            table.putInt(i, i);
        }
        table.putInt(0x10, (int) UnidbgPointer.nativeValue(_GetVersion));
        table.putInt(0x14, (int) UnidbgPointer.nativeValue(_DefineClass));
        table.putInt(0x18, (int) UnidbgPointer.nativeValue(_FindClass));
        table.putInt(0x1c, (int) UnidbgPointer.nativeValue(_FromReflectedMethod));
        table.putInt(0x20, (int) UnidbgPointer.nativeValue(_FromReflectedField));
        table.putInt(0x24, (int) UnidbgPointer.nativeValue(_ToReflectedMethod));
        table.putInt(0x28, (int) UnidbgPointer.nativeValue(_GetSuperclass));
        table.putInt(0x2c, (int) UnidbgPointer.nativeValue(_IsAssignableFrom));
        table.putInt(0x30, (int) UnidbgPointer.nativeValue(_ToReflectedField));
        table.putInt(0x34, (int) UnidbgPointer.nativeValue(_Throw));
        table.putInt(0x38, (int) UnidbgPointer.nativeValue(_ThrowNew));
        table.putInt(0x3c, (int) UnidbgPointer.nativeValue(_ExceptionOccurred));
        table.putInt(0x40, (int) UnidbgPointer.nativeValue(_ExceptionDescribe));
        table.putInt(0x44, (int) UnidbgPointer.nativeValue(_ExceptionClear));
        table.putInt(0x48, (int) UnidbgPointer.nativeValue(_FatalError));
        table.putInt(0x4c, (int) UnidbgPointer.nativeValue(_PushLocalFrame));
        table.putInt(0x50, (int) UnidbgPointer.nativeValue(_PopLocalFrame));
        table.putInt(0x54, (int) UnidbgPointer.nativeValue(_NewGlobalRef));
        table.putInt(0x58, (int) UnidbgPointer.nativeValue(_DeleteGlobalRef));
        table.putInt(0x5c, (int) UnidbgPointer.nativeValue(_DeleteLocalRef));
        table.putInt(0x60, (int) UnidbgPointer.nativeValue(_IsSameObject));
        table.putInt(0x64, (int) UnidbgPointer.nativeValue(_NewLocalRef));
        table.putInt(0x68, (int) UnidbgPointer.nativeValue(_EnsureLocalCapacity));
        table.putInt(0x6c, (int) UnidbgPointer.nativeValue(_AllocObject));
        table.putInt(0x70, (int) UnidbgPointer.nativeValue(_NewObject));
        table.putInt(0x74, (int) UnidbgPointer.nativeValue(_NewObjectV));
        table.putInt(0x78, (int) UnidbgPointer.nativeValue(_NewObjectA));
        table.putInt(0x7c, (int) UnidbgPointer.nativeValue(_GetObjectClass));
        table.putInt(0x80, (int) UnidbgPointer.nativeValue(_IsInstanceOf));
        table.putInt(0x84, (int) UnidbgPointer.nativeValue(_GetMethodID));
        table.putInt(0x88, (int) UnidbgPointer.nativeValue(_CallObjectMethod));
        table.putInt(0x8c, (int) UnidbgPointer.nativeValue(_CallObjectMethodV));
        table.putInt(0x90, (int) UnidbgPointer.nativeValue(_CallObjectMethodA));
        table.putInt(0x94, (int) UnidbgPointer.nativeValue(_CallBooleanMethod));
        table.putInt(0x98, (int) UnidbgPointer.nativeValue(_CallBooleanMethodV));
        table.putInt(0x9c, (int) UnidbgPointer.nativeValue(_CallBooleanMethodA));
        table.putInt(0xa0, (int) UnidbgPointer.nativeValue(_CallByteMethod));
        table.putInt(0xa4, (int) UnidbgPointer.nativeValue(_CallByteMethodV));
        table.putInt(0xa8, (int) UnidbgPointer.nativeValue(_CallByteMethodA));
        table.putInt(0xac, (int) UnidbgPointer.nativeValue(_CallCharMethod));
        table.putInt(0xb0, (int) UnidbgPointer.nativeValue(_CallCharMethodV));
        table.putInt(0xb4, (int) UnidbgPointer.nativeValue(_CallCharMethodA));
        table.putInt(0xb8, (int) UnidbgPointer.nativeValue(_CallShortMethod));
        table.putInt(0xbc, (int) UnidbgPointer.nativeValue(_CallShortMethodV));
        table.putInt(0xc0, (int) UnidbgPointer.nativeValue(_CallShortMethodA));
        table.putInt(0xc4, (int) UnidbgPointer.nativeValue(_CallIntMethod));
        table.putInt(0xc8, (int) UnidbgPointer.nativeValue(_CallIntMethodV));
        table.putInt(0xcc, (int) UnidbgPointer.nativeValue(_CallIntMethodA));
        table.putInt(0xd0, (int) UnidbgPointer.nativeValue(_CallLongMethod));
        table.putInt(0xd4, (int) UnidbgPointer.nativeValue(_CallLongMethodV));
        table.putInt(0xd8, (int) UnidbgPointer.nativeValue(_CallLongMethodA));
        table.putInt(0xdc, (int) UnidbgPointer.nativeValue(_CallFloatMethod));
        table.putInt(0xe0, (int) UnidbgPointer.nativeValue(_CallFloatMethodV));
        table.putInt(0xe4, (int) UnidbgPointer.nativeValue(_CallFloatMethodA));
        table.putInt(0xe8, (int) UnidbgPointer.nativeValue(_CallDoubleMethod));
        table.putInt(0xec, (int) UnidbgPointer.nativeValue(_CallDoubleMethodV));
        table.putInt(0xf0, (int) UnidbgPointer.nativeValue(_CallDoubleMethodA));
        table.putInt(0xf4, (int) UnidbgPointer.nativeValue(_CallVoidMethod));
        table.putInt(0xf8, (int) UnidbgPointer.nativeValue(_CallVoidMethodV));
        table.putInt(0xfc, (int) UnidbgPointer.nativeValue(_CallVoidMethodA));
        table.putInt(0x100, (int) UnidbgPointer.nativeValue(_CallNonvirtualObjectMethod));
        table.putInt(0x104, (int) UnidbgPointer.nativeValue(_CallNonvirtualObjectMethodV));
        table.putInt(0x108, (int) UnidbgPointer.nativeValue(_CallNonvirtualObjectMethodA));
        table.putInt(0x10c, (int) UnidbgPointer.nativeValue(_CallNonvirtualBooleanMethod));
        table.putInt(0x110, (int) UnidbgPointer.nativeValue(_CallNonvirtualBooleanMethodV));
        table.putInt(0x114, (int) UnidbgPointer.nativeValue(_CallNonvirtualBooleanMethodA));
        table.putInt(0x118, (int) UnidbgPointer.nativeValue(_CallNonvirtualByteMethod));
        table.putInt(0x11c, (int) UnidbgPointer.nativeValue(_CallNonvirtualByteMethodV));
        table.putInt(0x120, (int) UnidbgPointer.nativeValue(_CallNonvirtualByteMethodA));
        table.putInt(0x124, (int) UnidbgPointer.nativeValue(_CallNonvirtualCharMethod));
        table.putInt(0x128, (int) UnidbgPointer.nativeValue(_CallNonvirtualCharMethodV));
        table.putInt(0x12c, (int) UnidbgPointer.nativeValue(_CallNonvirtualCharMethodA));
        table.putInt(0x130, (int) UnidbgPointer.nativeValue(_CallNonvirtualShortMethod));
        table.putInt(0x134, (int) UnidbgPointer.nativeValue(_CallNonvirtualShortMethodV));
        table.putInt(0x138, (int) UnidbgPointer.nativeValue(_CallNonvirtualShortMethodA));
        table.putInt(0x13c, (int) UnidbgPointer.nativeValue(_CallNonvirtualIntMethod));
        table.putInt(0x140, (int) UnidbgPointer.nativeValue(_CallNonvirtualIntMethodV));
        table.putInt(0x144, (int) UnidbgPointer.nativeValue(_CallNonvirtualIntMethodA));
        table.putInt(0x148, (int) UnidbgPointer.nativeValue(_CallNonvirtualLongMethod));
        table.putInt(0x14c, (int) UnidbgPointer.nativeValue(_CallNonvirtualLongMethodV));
        table.putInt(0x150, (int) UnidbgPointer.nativeValue(_CallNonvirtualLongMethodA));
        table.putInt(0x154, (int) UnidbgPointer.nativeValue(_CallNonvirtualFloatMethod));
        table.putInt(0x158, (int) UnidbgPointer.nativeValue(_CallNonvirtualFloatMethodV));
        table.putInt(0x15c, (int) UnidbgPointer.nativeValue(_CallNonvirtualFloatMethodA));
        table.putInt(0x160, (int) UnidbgPointer.nativeValue(_CallNonvirtualDoubleMethod));
        table.putInt(0x164, (int) UnidbgPointer.nativeValue(_CallNonvirtualDoubleMethodV));
        table.putInt(0x168, (int) UnidbgPointer.nativeValue(_CallNonvirtualDoubleMethodA));
        table.putInt(0x16c, (int) UnidbgPointer.nativeValue(_CallNonvirtualVoidMethod));
        table.putInt(0x170, (int) UnidbgPointer.nativeValue(_CallNonvirtualVoidMethodV));
        table.putInt(0x174, (int) UnidbgPointer.nativeValue(_CallNonVirtualVoidMethodA));
        table.putInt(0x178, (int) UnidbgPointer.nativeValue(_GetFieldID));
        table.putInt(0x17c, (int) UnidbgPointer.nativeValue(_GetObjectField));
        table.putInt(0x180, (int) UnidbgPointer.nativeValue(_GetBooleanField));
        table.putInt(0x184, (int) UnidbgPointer.nativeValue(_GetByteField));
        table.putInt(0x188, (int) UnidbgPointer.nativeValue(_GetCharField));
        table.putInt(0x18c, (int) UnidbgPointer.nativeValue(_GetShortField));
        table.putInt(0x190, (int) UnidbgPointer.nativeValue(_GetIntField));
        table.putInt(0x194, (int) UnidbgPointer.nativeValue(_GetLongField));
        table.putInt(0x198, (int) UnidbgPointer.nativeValue(_GetFloatField));
        table.putInt(0x19c, (int) UnidbgPointer.nativeValue(_GetDoubleField));
        table.putInt(0x1a0, (int) UnidbgPointer.nativeValue(_SetObjectField));
        table.putInt(0x1a4, (int) UnidbgPointer.nativeValue(_SetBooleanField));
        table.putInt(0x1a8, (int) UnidbgPointer.nativeValue(_SetByteField));
        table.putInt(0x1ac, (int) UnidbgPointer.nativeValue(_SetCharField));
        table.putInt(0x1b0, (int) UnidbgPointer.nativeValue(_SetShortField));
        table.putInt(0x1b4, (int) UnidbgPointer.nativeValue(_SetIntField));
        table.putInt(0x1b8, (int) UnidbgPointer.nativeValue(_SetLongField));
        table.putInt(0x1bc, (int) UnidbgPointer.nativeValue(_SetFloatField));
        table.putInt(0x1c0, (int) UnidbgPointer.nativeValue(_SetDoubleField));
        table.putInt(0x1c4, (int) UnidbgPointer.nativeValue(_GetStaticMethodID));
        table.putInt(0x1c8, (int) UnidbgPointer.nativeValue(_CallStaticObjectMethod));
        table.putInt(0x1cc, (int) UnidbgPointer.nativeValue(_CallStaticObjectMethodV));
        table.putInt(0x1d0, (int) UnidbgPointer.nativeValue(_CallStaticObjectMethodA));
        table.putInt(0x1d4, (int) UnidbgPointer.nativeValue(_CallStaticBooleanMethod));
        table.putInt(0x1d8, (int) UnidbgPointer.nativeValue(_CallStaticBooleanMethodV));
        table.putInt(0x1dc, (int) UnidbgPointer.nativeValue(_CallStaticBooleanMethodA));
        table.putInt(0x1e0, (int) UnidbgPointer.nativeValue(_CallStaticByteMethod));
        table.putInt(0x1e4, (int) UnidbgPointer.nativeValue(_CallStaticByteMethodV));
        table.putInt(0x1e8, (int) UnidbgPointer.nativeValue(_CallStaticByteMethodA));
        table.putInt(0x1ec, (int) UnidbgPointer.nativeValue(_CallStaticCharMethod));
        table.putInt(0x1f0, (int) UnidbgPointer.nativeValue(_CallStaticCharMethodV));
        table.putInt(0x1f4, (int) UnidbgPointer.nativeValue(_CallStaticCharMethodA));
        table.putInt(0x1f8, (int) UnidbgPointer.nativeValue(_CallStaticShortMethod));
        table.putInt(0x1fc, (int) UnidbgPointer.nativeValue(_CallStaticShortMethodV));
        table.putInt(0x200, (int) UnidbgPointer.nativeValue(_CallStaticShortMethodA));
        table.putInt(0x204, (int) UnidbgPointer.nativeValue(_CallStaticIntMethod));
        table.putInt(0x208, (int) UnidbgPointer.nativeValue(_CallStaticIntMethodV));
        table.putInt(0x20c, (int) UnidbgPointer.nativeValue(_CallStaticIntMethodA));
        table.putInt(0x210, (int) UnidbgPointer.nativeValue(_CallStaticLongMethod));
        table.putInt(0x214, (int) UnidbgPointer.nativeValue(_CallStaticLongMethodV));
        table.putInt(0x218, (int) UnidbgPointer.nativeValue(_CallStaticLongMethodA));
        table.putInt(0x21c, (int) UnidbgPointer.nativeValue(_CallStaticFloatMethod));
        table.putInt(0x220, (int) UnidbgPointer.nativeValue(_CallStaticFloatMethodV));
        table.putInt(0x224, (int) UnidbgPointer.nativeValue(_CallStaticFloatMethodA));
        table.putInt(0x228, (int) UnidbgPointer.nativeValue(_CallStaticDoubleMethod));
        table.putInt(0x22c, (int) UnidbgPointer.nativeValue(_CallStaticDoubleMethodV));
        table.putInt(0x230, (int) UnidbgPointer.nativeValue(_CallStaticDoubleMethodA));
        table.putInt(0x234, (int) UnidbgPointer.nativeValue(_CallStaticVoidMethod));
        table.putInt(0x238, (int) UnidbgPointer.nativeValue(_CallStaticVoidMethodV));
        table.putInt(0x23c, (int) UnidbgPointer.nativeValue(_CallStaticVoidMethodA));
        table.putInt(0x240, (int) UnidbgPointer.nativeValue(_GetStaticFieldID));
        table.putInt(0x244, (int) UnidbgPointer.nativeValue(_GetStaticObjectField));
        table.putInt(0x248, (int) UnidbgPointer.nativeValue(_GetStaticBooleanField));
        table.putInt(0x24c, (int) UnidbgPointer.nativeValue(_GetStaticByteField));
        table.putInt(0x250, (int) UnidbgPointer.nativeValue(_GetStaticCharField));
        table.putInt(0x254, (int) UnidbgPointer.nativeValue(_GetStaticShortField));
        table.putInt(0x258, (int) UnidbgPointer.nativeValue(_GetStaticIntField));
        table.putInt(0x25c, (int) UnidbgPointer.nativeValue(_GetStaticLongField));
        table.putInt(0x260, (int) UnidbgPointer.nativeValue(_GetStaticFloatField));
        table.putInt(0x264, (int) UnidbgPointer.nativeValue(_GetStaticDoubleField));
        table.putInt(0x268, (int) UnidbgPointer.nativeValue(_SetStaticObjectField));
        table.putInt(0x26c, (int) UnidbgPointer.nativeValue(_SetStaticBooleanField));
        table.putInt(0x270, (int) UnidbgPointer.nativeValue(_SetStaticByteField));
        table.putInt(0x274, (int) UnidbgPointer.nativeValue(_SetStaticCharField));
        table.putInt(0x278, (int) UnidbgPointer.nativeValue(_SetStaticShortField));
        table.putInt(0x27c, (int) UnidbgPointer.nativeValue(_SetStaticIntField));
        table.putInt(0x280, (int) UnidbgPointer.nativeValue(_SetStaticLongField));
        table.putInt(0x284, (int) UnidbgPointer.nativeValue(_SetStaticFloatField));
        table.putInt(0x288, (int) UnidbgPointer.nativeValue(_SetStaticDoubleField));
        table.putInt(0x28c, (int) UnidbgPointer.nativeValue(_NewString));
        table.putInt(0x290, (int) UnidbgPointer.nativeValue(_GetStringLength));
        table.putInt(0x294, (int) UnidbgPointer.nativeValue(_GetStringChars));
        table.putInt(0x298, (int) UnidbgPointer.nativeValue(_ReleaseStringChars));
        table.putInt(0x29c, (int) UnidbgPointer.nativeValue(_NewStringUTF));
        table.putInt(0x2a0, (int) UnidbgPointer.nativeValue(_GetStringUTFLength));
        table.putInt(0x2a4, (int) UnidbgPointer.nativeValue(_GetStringUTFChars));
        table.putInt(0x2a8, (int) UnidbgPointer.nativeValue(_ReleaseStringUTFChars));
        table.putInt(0x2ac, (int) UnidbgPointer.nativeValue(_GetArrayLength));
        table.putInt(0x2b0, (int) UnidbgPointer.nativeValue(_NewObjectArray));
        table.putInt(0x2b4, (int) UnidbgPointer.nativeValue(_GetObjectArrayElement));
        table.putInt(0x2b8, (int) UnidbgPointer.nativeValue(_SetObjectArrayElement));
        table.putInt(0x2bc, (int) UnidbgPointer.nativeValue(_NewBooleanArray));
        table.putInt(0x2c0, (int) UnidbgPointer.nativeValue(_NewByteArray));
        table.putInt(0x2c4, (int) UnidbgPointer.nativeValue(_NewCharArray));
        table.putInt(0x2c8, (int) UnidbgPointer.nativeValue(_NewShortArray));
        table.putInt(0x2cc, (int) UnidbgPointer.nativeValue(_NewIntArray));
        table.putInt(0x2d0, (int) UnidbgPointer.nativeValue(_NewLongArray));
        table.putInt(0x2d4, (int) UnidbgPointer.nativeValue(_NewFloatArray));
        table.putInt(0x2d8, (int) UnidbgPointer.nativeValue(_NewDoubleArray));
        table.putInt(0x2dc, (int) UnidbgPointer.nativeValue(_GetBooleanArrayElements));
        table.putInt(0x2e0, (int) UnidbgPointer.nativeValue(_GetByteArrayElements));
        table.putInt(0x2e4, (int) UnidbgPointer.nativeValue(_GetCharArrayElements));
        table.putInt(0x2e8, (int) UnidbgPointer.nativeValue(_GetShortArrayElements));
        table.putInt(0x2ec, (int) UnidbgPointer.nativeValue(_GetIntArrayElements));
        table.putInt(0x2f0, (int) UnidbgPointer.nativeValue(_GetLongArrayElements));
        table.putInt(0x2f4, (int) UnidbgPointer.nativeValue(_GetFloatArrayElements));
        table.putInt(0x2f8, (int) UnidbgPointer.nativeValue(_GetDoubleArrayElements));
        table.putInt(0x2fc, (int) UnidbgPointer.nativeValue(_ReleaseBooleanArrayElements));
        table.putInt(0x300, (int) UnidbgPointer.nativeValue(_ReleaseByteArrayElements));
        table.putInt(0x304, (int) UnidbgPointer.nativeValue(_ReleaseCharArrayElements));
        table.putInt(0x308, (int) UnidbgPointer.nativeValue(_ReleaseShortArrayElements));
        table.putInt(0x30c, (int) UnidbgPointer.nativeValue(_ReleaseIntArrayElements));
        table.putInt(0x310, (int) UnidbgPointer.nativeValue(_ReleaseLongArrayElements));
        table.putInt(0x314, (int) UnidbgPointer.nativeValue(_ReleaseFloatArrayElements));
        table.putInt(0x318, (int) UnidbgPointer.nativeValue(_ReleaseDoubleArrayElements));
        table.putInt(0x31c, (int) UnidbgPointer.nativeValue(_GetBooleanArrayRegion));
        table.putInt(0x320, (int) UnidbgPointer.nativeValue(_GetByteArrayRegion));
        table.putInt(0x324, (int) UnidbgPointer.nativeValue(_GetCharArrayRegion));
        table.putInt(0x328, (int) UnidbgPointer.nativeValue(_GetShortArrayRegion));
        table.putInt(0x32c, (int) UnidbgPointer.nativeValue(_GetIntArrayRegion));
        table.putInt(0x330, (int) UnidbgPointer.nativeValue(_GetLongArrayRegion));
        table.putInt(0x334, (int) UnidbgPointer.nativeValue(_GetFloatArrayRegion));
        table.putInt(0x338, (int) UnidbgPointer.nativeValue(_GetDoubleArrayRegion));
        table.putInt(0x33c, (int) UnidbgPointer.nativeValue(_SetBooleanArrayRegion));
        table.putInt(0x340, (int) UnidbgPointer.nativeValue(_SetByteArrayRegion));
        table.putInt(0x344, (int) UnidbgPointer.nativeValue(_SetCharArrayRegion));
        table.putInt(0x348, (int) UnidbgPointer.nativeValue(_SetShortArrayRegion));
        table.putInt(0x34c, (int) UnidbgPointer.nativeValue(_SetIntArrayRegion));
        table.putInt(0x350, (int) UnidbgPointer.nativeValue(_SetLongArrayRegion));
        table.putInt(0x354, (int) UnidbgPointer.nativeValue(_SetFloatArrayRegion));
        table.putInt(0x358, (int) UnidbgPointer.nativeValue(_SetDoubleArrayRegion));
        table.putInt(0x35c, (int) UnidbgPointer.nativeValue(_RegisterNatives));
        table.putInt(0x360, (int) UnidbgPointer.nativeValue(_UnregisterNatives));
        table.putInt(0x364, (int) UnidbgPointer.nativeValue(_MonitorEnter));
        table.putInt(0x368, (int) UnidbgPointer.nativeValue(_MonitorExit));
        table.putInt(0x36c, (int) UnidbgPointer.nativeValue(_GetJavaVM));
        table.putInt(0x370, (int) UnidbgPointer.nativeValue(_GetStringRegion));
        table.putInt(0x374, (int) UnidbgPointer.nativeValue(_GetStringUTFRegion));
        table.putInt(0x378, (int) UnidbgPointer.nativeValue(_GetPrimitiveArrayCritical));
        table.putInt(0x37c, (int) UnidbgPointer.nativeValue(_ReleasePrimitiveArrayCritical));
        table.putInt(0x380, (int) UnidbgPointer.nativeValue(_GetStringCritical));
        table.putInt(0x384, (int) UnidbgPointer.nativeValue(_ReleaseStringCritical));
        table.putInt(0x388, (int) UnidbgPointer.nativeValue(_NewWeakGlobalRef));
        table.putInt(0x38c, (int) UnidbgPointer.nativeValue(_DeleteWeakGlobalRef));
        table.putInt(0x390, (int) UnidbgPointer.nativeValue(_ExceptionCheck));
        table.putInt(0x394, (int) UnidbgPointer.nativeValue(_NewDirectByteBuffer));
        table.putInt(0x398, (int) UnidbgPointer.nativeValue(_GetDirectBufferAddress));
        table.putInt(0x39c, (int) UnidbgPointer.nativeValue(_GetDirectBufferCapacity));
        table.putInt(0x3a0, (int) UnidbgPointer.nativeValue(_GetObjectRefType));
        table.putInt(last, (int) UnidbgPointer.nativeValue(_GetModule));

        // Publish the fully initialized table in one backend write.
        impl.write(table.array());

        _JNIEnv = svcMemory.allocate(emulator.getPointerSize(), "_JNIEnv");
        _JNIEnv.setPointer(0, impl);

        UnidbgPointer _AttachCurrentThread = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer vm = context.getPointerArg(0);
                Pointer env = context.getPointerArg(1);
                Pointer args = context.getPointerArg(2); // JavaVMAttachArgs*
                if (log.isDebugEnabled()) {
                    log.debug("AttachCurrentThread vm={}, env={}, args={}", vm, env.getPointer(0), args);
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnidbgPointer _GetEnv = svcMemory.registerSvc(new ArmSvc("_GetEnv") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer vm = context.getPointerArg(0);
                Pointer env = context.getPointerArg(1);
                int version = context.getIntArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetEnv vm={}, env={}, version=0x{}", vm, env.getPointer(0), Integer.toHexString(version));
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnidbgPointer _JNIInvokeInterface = svcMemory.allocate(emulator.getPointerSize() * 8, "_JNIInvokeInterface");
        for (int i = 0; i < emulator.getPointerSize() * 8; i += emulator.getPointerSize()) {
            _JNIInvokeInterface.setInt(i, i);
        }
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 4L, _AttachCurrentThread);
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 6L, _GetEnv);

        _JavaVM.setPointer(0, _JNIInvokeInterface);

        if (log.isDebugEnabled()) {
            log.debug("_JavaVM={}, _JNIInvokeInterface={}, _JNIEnv={}", _JavaVM, _JNIInvokeInterface, _JNIEnv);
        }
    }

    @Override
    public Pointer getJavaVM() {
        return _JavaVM;
    }

    @Override
    public Pointer getJNIEnv() {
        return _JNIEnv;
    }

    byte[] loadLibraryData(Apk apk, String soName) {
        byte[] soData = apk.getFileData("lib/armeabi-v7a/" + soName);
        if (soData != null) {
            if (log.isDebugEnabled()) {
                log.debug("resolve armeabi-v7a library: {}", soName);
            }
            return soData;
        }
        soData = apk.getFileData("lib/armeabi/" + soName);
        if (soData != null && log.isDebugEnabled()) {
            log.debug("resolve armeabi library: {}", soName);
        }
        return soData;
    }
}
