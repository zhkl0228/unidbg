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
                    log.debug("JNIEnv->GetSuperClass was called, class = {} According to Java Native Interface Specification, If clazz specifies the class Object, returns NULL.", dvmClass.getClassName());
                    throw new BackendException();
                }
                DvmClass superClass = dvmClass.getSuperclass();
                if (superClass == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("JNIEnv->GetSuperClass was called, class = {}, superClass get failed.", dvmClass.getClassName());
                    }
                    throw new BackendException();
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

                return addLocalObject(new ArrayObject(array));
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
                throw new UnsupportedOperationException();
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
                throw new UnsupportedOperationException();
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
                throw new UnsupportedOperationException();
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
                throw new UnsupportedOperationException();
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
                throw new UnsupportedOperationException();
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
                throw new UnsupportedOperationException();
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
        for (int i = 0; i <= last; i += 4) {
            impl.setInt(i, i);
        }
        impl.setPointer(0x10, _GetVersion);
        impl.setPointer(0x14, _DefineClass);
        impl.setPointer(0x18, _FindClass);
        impl.setPointer(0x1c, _FromReflectedMethod);
        impl.setPointer(0x20, _FromReflectedField);
        impl.setPointer(0x24, _ToReflectedMethod);
        impl.setPointer(0x28, _GetSuperclass);
        impl.setPointer(0x2c, _IsAssignableFrom);
        impl.setPointer(0x30, _ToReflectedField);
        impl.setPointer(0x34, _Throw);
        impl.setPointer(0x38, _ThrowNew);
        impl.setPointer(0x3c, _ExceptionOccurred);
        impl.setPointer(0x40, _ExceptionDescribe);
        impl.setPointer(0x44, _ExceptionClear);
        impl.setPointer(0x48, _FatalError);
        impl.setPointer(0x4c, _PushLocalFrame);
        impl.setPointer(0x50, _PopLocalFrame);
        impl.setPointer(0x54, _NewGlobalRef);
        impl.setPointer(0x58, _DeleteGlobalRef);
        impl.setPointer(0x5c, _DeleteLocalRef);
        impl.setPointer(0x60, _IsSameObject);
        impl.setPointer(0x64, _NewLocalRef);
        impl.setPointer(0x68, _EnsureLocalCapacity);
        impl.setPointer(0x6c, _AllocObject);
        impl.setPointer(0x70, _NewObject);
        impl.setPointer(0x74, _NewObjectV);
        impl.setPointer(0x78, _NewObjectA);
        impl.setPointer(0x7c, _GetObjectClass);
        impl.setPointer(0x80, _IsInstanceOf);
        impl.setPointer(0x84, _GetMethodID);
        impl.setPointer(0x88, _CallObjectMethod);
        impl.setPointer(0x8c, _CallObjectMethodV);
        impl.setPointer(0x90, _CallObjectMethodA);
        impl.setPointer(0x94, _CallBooleanMethod);
        impl.setPointer(0x98, _CallBooleanMethodV);
        impl.setPointer(0x9c, _CallBooleanMethodA);
        impl.setPointer(0xa0, _CallByteMethod);
        impl.setPointer(0xa4, _CallByteMethodV);
        impl.setPointer(0xa8, _CallByteMethodA);
        impl.setPointer(0xac, _CallCharMethod);
        impl.setPointer(0xb0, _CallCharMethodV);
        impl.setPointer(0xb4, _CallCharMethodA);
        impl.setPointer(0xb8, _CallShortMethod);
        impl.setPointer(0xbc, _CallShortMethodV);
        impl.setPointer(0xc0, _CallShortMethodA);
        impl.setPointer(0xc4, _CallIntMethod);
        impl.setPointer(0xc8, _CallIntMethodV);
        impl.setPointer(0xcc, _CallIntMethodA);
        impl.setPointer(0xd0, _CallLongMethod);
        impl.setPointer(0xd4, _CallLongMethodV);
        impl.setPointer(0xd8, _CallLongMethodA);
        impl.setPointer(0xdc, _CallFloatMethod);
        impl.setPointer(0xe0, _CallFloatMethodV);
        impl.setPointer(0xe4, _CallFloatMethodA);
        impl.setPointer(0xe8, _CallDoubleMethod);
        impl.setPointer(0xec, _CallDoubleMethodV);
        impl.setPointer(0xf0, _CallDoubleMethodA);
        impl.setPointer(0xf4, _CallVoidMethod);
        impl.setPointer(0xf8, _CallVoidMethodV);
        impl.setPointer(0xfc, _CallVoidMethodA);
        impl.setPointer(0x100, _CallNonvirtualObjectMethod);
        impl.setPointer(0x104, _CallNonvirtualObjectMethodV);
        impl.setPointer(0x108, _CallNonvirtualObjectMethodA);
        impl.setPointer(0x10c, _CallNonvirtualBooleanMethod);
        impl.setPointer(0x110, _CallNonvirtualBooleanMethodV);
        impl.setPointer(0x114, _CallNonvirtualBooleanMethodA);
        impl.setPointer(0x118, _CallNonvirtualByteMethod);
        impl.setPointer(0x11c, _CallNonvirtualByteMethodV);
        impl.setPointer(0x120, _CallNonvirtualByteMethodA);
        impl.setPointer(0x124, _CallNonvirtualCharMethod);
        impl.setPointer(0x128, _CallNonvirtualCharMethodV);
        impl.setPointer(0x12c, _CallNonvirtualCharMethodA);
        impl.setPointer(0x130, _CallNonvirtualShortMethod);
        impl.setPointer(0x134, _CallNonvirtualShortMethodV);
        impl.setPointer(0x138, _CallNonvirtualShortMethodA);
        impl.setPointer(0x13c, _CallNonvirtualIntMethod);
        impl.setPointer(0x140, _CallNonvirtualIntMethodV);
        impl.setPointer(0x144, _CallNonvirtualIntMethodA);
        impl.setPointer(0x148, _CallNonvirtualLongMethod);
        impl.setPointer(0x14c, _CallNonvirtualLongMethodV);
        impl.setPointer(0x150, _CallNonvirtualLongMethodA);
        impl.setPointer(0x154, _CallNonvirtualFloatMethod);
        impl.setPointer(0x158, _CallNonvirtualFloatMethodV);
        impl.setPointer(0x15c, _CallNonvirtualFloatMethodA);
        impl.setPointer(0x160, _CallNonvirtualDoubleMethod);
        impl.setPointer(0x164, _CallNonvirtualDoubleMethodV);
        impl.setPointer(0x168, _CallNonvirtualDoubleMethodA);
        impl.setPointer(0x16c, _CallNonvirtualVoidMethod);
        impl.setPointer(0x170, _CallNonvirtualVoidMethodV);
        impl.setPointer(0x174, _CallNonVirtualVoidMethodA);
        impl.setPointer(0x178, _GetFieldID);
        impl.setPointer(0x17c, _GetObjectField);
        impl.setPointer(0x180, _GetBooleanField);
        impl.setPointer(0x184, _GetByteField);
        impl.setPointer(0x188, _GetCharField);
        impl.setPointer(0x18c, _GetShortField);
        impl.setPointer(0x190, _GetIntField);
        impl.setPointer(0x194, _GetLongField);
        impl.setPointer(0x198, _GetFloatField);
        impl.setPointer(0x19c, _GetDoubleField);
        impl.setPointer(0x1a0, _SetObjectField);
        impl.setPointer(0x1a4, _SetBooleanField);
        impl.setPointer(0x1a8, _SetByteField);
        impl.setPointer(0x1ac, _SetCharField);
        impl.setPointer(0x1b0, _SetShortField);
        impl.setPointer(0x1b4, _SetIntField);
        impl.setPointer(0x1b8, _SetLongField);
        impl.setPointer(0x1bc, _SetFloatField);
        impl.setPointer(0x1c0, _SetDoubleField);
        impl.setPointer(0x1c4, _GetStaticMethodID);
        impl.setPointer(0x1c8, _CallStaticObjectMethod);
        impl.setPointer(0x1cc, _CallStaticObjectMethodV);
        impl.setPointer(0x1d0, _CallStaticObjectMethodA);
        impl.setPointer(0x1d4, _CallStaticBooleanMethod);
        impl.setPointer(0x1d8, _CallStaticBooleanMethodV);
        impl.setPointer(0x1dc, _CallStaticBooleanMethodA);
        impl.setPointer(0x1e0, _CallStaticByteMethod);
        impl.setPointer(0x1e4, _CallStaticByteMethodV);
        impl.setPointer(0x1e8, _CallStaticByteMethodA);
        impl.setPointer(0x1ec, _CallStaticCharMethod);
        impl.setPointer(0x1f0, _CallStaticCharMethodV);
        impl.setPointer(0x1f4, _CallStaticCharMethodA);
        impl.setPointer(0x1f8, _CallStaticShortMethod);
        impl.setPointer(0x1fc, _CallStaticShortMethodV);
        impl.setPointer(0x200, _CallStaticShortMethodA);
        impl.setPointer(0x204, _CallStaticIntMethod);
        impl.setPointer(0x208, _CallStaticIntMethodV);
        impl.setPointer(0x20c, _CallStaticIntMethodA);
        impl.setPointer(0x210, _CallStaticLongMethod);
        impl.setPointer(0x214, _CallStaticLongMethodV);
        impl.setPointer(0x218, _CallStaticLongMethodA);
        impl.setPointer(0x21c, _CallStaticFloatMethod);
        impl.setPointer(0x220, _CallStaticFloatMethodV);
        impl.setPointer(0x224, _CallStaticFloatMethodA);
        impl.setPointer(0x228, _CallStaticDoubleMethod);
        impl.setPointer(0x22c, _CallStaticDoubleMethodV);
        impl.setPointer(0x230, _CallStaticDoubleMethodA);
        impl.setPointer(0x234, _CallStaticVoidMethod);
        impl.setPointer(0x238, _CallStaticVoidMethodV);
        impl.setPointer(0x23c, _CallStaticVoidMethodA);
        impl.setPointer(0x240, _GetStaticFieldID);
        impl.setPointer(0x244, _GetStaticObjectField);
        impl.setPointer(0x248, _GetStaticBooleanField);
        impl.setPointer(0x24c, _GetStaticByteField);
        impl.setPointer(0x250, _GetStaticCharField);
        impl.setPointer(0x254, _GetStaticShortField);
        impl.setPointer(0x258, _GetStaticIntField);
        impl.setPointer(0x25c, _GetStaticLongField);
        impl.setPointer(0x260, _GetStaticFloatField);
        impl.setPointer(0x264, _GetStaticDoubleField);
        impl.setPointer(0x268, _SetStaticObjectField);
        impl.setPointer(0x26c, _SetStaticBooleanField);
        impl.setPointer(0x270, _SetStaticByteField);
        impl.setPointer(0x274, _SetStaticCharField);
        impl.setPointer(0x278, _SetStaticShortField);
        impl.setPointer(0x27c, _SetStaticIntField);
        impl.setPointer(0x280, _SetStaticLongField);
        impl.setPointer(0x284, _SetStaticFloatField);
        impl.setPointer(0x288, _SetStaticDoubleField);
        impl.setPointer(0x28c, _NewString);
        impl.setPointer(0x290, _GetStringLength);
        impl.setPointer(0x294, _GetStringChars);
        impl.setPointer(0x298, _ReleaseStringChars);
        impl.setPointer(0x29c, _NewStringUTF);
        impl.setPointer(0x2a0, _GetStringUTFLength);
        impl.setPointer(0x2a4, _GetStringUTFChars);
        impl.setPointer(0x2a8, _ReleaseStringUTFChars);
        impl.setPointer(0x2ac, _GetArrayLength);
        impl.setPointer(0x2b0, _NewObjectArray);
        impl.setPointer(0x2b4, _GetObjectArrayElement);
        impl.setPointer(0x2b8, _SetObjectArrayElement);
        impl.setPointer(0x2bc, _NewBooleanArray);
        impl.setPointer(0x2c0, _NewByteArray);
        impl.setPointer(0x2c4, _NewCharArray);
        impl.setPointer(0x2c8, _NewShortArray);
        impl.setPointer(0x2cc, _NewIntArray);
        impl.setPointer(0x2d0, _NewLongArray);
        impl.setPointer(0x2d4, _NewFloatArray);
        impl.setPointer(0x2d8, _NewDoubleArray);
        impl.setPointer(0x2dc, _GetBooleanArrayElements);
        impl.setPointer(0x2e0, _GetByteArrayElements);
        impl.setPointer(0x2e4, _GetCharArrayElements);
        impl.setPointer(0x2e8, _GetShortArrayElements);
        impl.setPointer(0x2ec, _GetIntArrayElements);
        impl.setPointer(0x2f0, _GetLongArrayElements);
        impl.setPointer(0x2f4, _GetFloatArrayElements);
        impl.setPointer(0x2f8, _GetDoubleArrayElements);
        impl.setPointer(0x2fc, _ReleaseBooleanArrayElements);
        impl.setPointer(0x300, _ReleaseByteArrayElements);
        impl.setPointer(0x304, _ReleaseCharArrayElements);
        impl.setPointer(0x308, _ReleaseShortArrayElements);
        impl.setPointer(0x30c, _ReleaseIntArrayElements);
        impl.setPointer(0x310, _ReleaseLongArrayElements);
        impl.setPointer(0x314, _ReleaseFloatArrayElements);
        impl.setPointer(0x318, _ReleaseDoubleArrayElements);
        impl.setPointer(0x31c, _GetBooleanArrayRegion);
        impl.setPointer(0x320, _GetByteArrayRegion);
        impl.setPointer(0x324, _GetCharArrayRegion);
        impl.setPointer(0x328, _GetShortArrayRegion);
        impl.setPointer(0x32c, _GetIntArrayRegion);
        impl.setPointer(0x330, _GetLongArrayRegion);
        impl.setPointer(0x334, _GetFloatArrayRegion);
        impl.setPointer(0x338, _GetDoubleArrayRegion);
        impl.setPointer(0x33c, _SetBooleanArrayRegion);
        impl.setPointer(0x340, _SetByteArrayRegion);
        impl.setPointer(0x344, _SetCharArrayRegion);
        impl.setPointer(0x348, _SetShortArrayRegion);
        impl.setPointer(0x34c, _SetIntArrayRegion);
        impl.setPointer(0x350, _SetLongArrayRegion);
        impl.setPointer(0x354, _SetFloatArrayRegion);
        impl.setPointer(0x358, _SetDoubleArrayRegion);
        impl.setPointer(0x35c, _RegisterNatives);
        impl.setPointer(0x360, _UnregisterNatives);
        impl.setPointer(0x364, _MonitorEnter);
        impl.setPointer(0x368, _MonitorExit);
        impl.setPointer(0x36c, _GetJavaVM);
        impl.setPointer(0x370, _GetStringRegion);
        impl.setPointer(0x374, _GetStringUTFRegion);
        impl.setPointer(0x378, _GetPrimitiveArrayCritical);
        impl.setPointer(0x37c, _ReleasePrimitiveArrayCritical);
        impl.setPointer(0x380, _GetStringCritical);
        impl.setPointer(0x384, _ReleaseStringCritical);
        impl.setPointer(0x388, _NewWeakGlobalRef);
        impl.setPointer(0x38c, _DeleteWeakGlobalRef);
        impl.setPointer(0x390, _ExceptionCheck);
        impl.setPointer(0x394, _NewDirectByteBuffer);
        impl.setPointer(0x398, _GetDirectBufferAddress);
        impl.setPointer(0x39c, _GetDirectBufferCapacity);
        impl.setPointer(0x3a0, _GetObjectRefType);
        impl.setPointer(last, _GetModule);

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
