package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.dvm.apk.Apk;
import com.github.unidbg.linux.android.dvm.array.*;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DalvikVM64 extends BaseVM implements VM {

    private static final Log log = LogFactory.getLog(DalvikVM64.class);

    private final UnidbgPointer _JavaVM;
    private final UnidbgPointer _JNIEnv;

    public DalvikVM64(Emulator<?> emulator, File apkFile) {
        super(emulator, apkFile);

        final SvcMemory svcMemory = emulator.getSvcMemory();
        _JavaVM = svcMemory.allocate(emulator.getPointerSize(), "_JavaVM");

        Pointer _FindClass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Arm64RegisterContext context = emulator.getContext();
                Pointer env = context.getXPointer(0);
                Pointer className = context.getXPointer(1);
                String name = className.getString(0);

                boolean notFound = notFoundClassSet.contains(name);
                if (verbose) {
                    if (notFound) {
                        System.out.printf("JNIEnv->FindNoClass(%s) was called from %s%n", name, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    } else {
                        System.out.printf("JNIEnv->FindClass(%s) was called from %s%n", name, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                }

                if (notFound) {
                    throwable = resolveClass("java/lang/NoClassDefFoundError").newObject(name);
                    return 0;
                }

                DvmClass dvmClass = resolveClass(name);
                long hash = dvmClass.hashCode() & 0xffffffffL;
                if (log.isDebugEnabled()) {
                    log.debug("FindClass env=" + env + ", className=" + name + ", hash=0x" + Long.toHexString(hash));
                }
                return hash;
            }
        });

        Pointer _ToReflectedMethod = svcMemory.registerSvc(new Arm64Svc() {
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
                    log.debug("ToReflectedMethod clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->ToReflectedMethod(%s, \"%s\", %s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, dvmMethod.isStatic ? "is static" : "not static", UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }

                    return addLocalObject(dvmMethod.toReflectedMethod());
                }
            }
        }) ;

        Pointer _Throw = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                log.warn("Throw object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getObjectType());
                throwable = dvmObject;
                return 0;
            }
        });

        Pointer _ExceptionOccurred = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionOccurred");
                }
                return throwable == null ? JNI_NULL : (throwable.hashCode() & 0xffffffffL);
            }
        });

        Pointer _ExceptionClear = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionClear");
                }
                throwable = null;
                return 0;
            }
        });

        Pointer _PushLocalFrame = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                int capacity = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("PushLocalFrame capacity=" + capacity);
                }
                return JNI_OK;
            }
        });

        Pointer _PopLocalFrame = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer jresult = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (log.isDebugEnabled()) {
                    log.debug("PopLocalFrame jresult=" + jresult);
                }
                return jresult == null ? 0 : jresult.toIntPeer();
            }
        });

        Pointer _NewGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewGlobalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                addObject(dvmObject, true);
                return object.toIntPeer();
            }
        });

        Pointer _DeleteGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteGlobalRef object=" + object);
                }
                DvmObject<?> obj = globalObjectMap.remove(object.toIntPeer());
                if (obj != null) {
                    obj.onDeleteRef();
                }
                return 0;
            }
        });

        Pointer _DeleteLocalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteLocalRef object=" + object);
                }
                DvmObject<?> obj = localObjectMap.remove(object.toIntPeer());
                if (obj != null) {
                    obj.onDeleteRef();
                }
                return 0;
            }
        });

        Pointer _IsSameObject = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer ref1 = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer ref2 = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("IsSameObject ref1=" + ref1 + ", ref2=" + ref2);
                }
                return ref1 == ref2 || ref1.equals(ref2) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _NewLocalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewLocalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewLocalRef(%s) was called from %s%n", dvmObject, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                return object.toIntPeer();
            }
        });

        Pointer _EnsureLocalCapacity = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                int capacity = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("EnsureLocalCapacity capacity=" + capacity);
                }
                return 0;
            }
        });

        Pointer _NewObject = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->NewObject(%s, %s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return dvmMethod.newObject(ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _NewObjectV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.newObjectV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->NewObjectV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetObjectClass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectClass object=" + object + ", dvmObject=" + dvmObject);
                }
                if (dvmObject == null) {
                    throw new BackendException();
                } else {
                    DvmClass dvmClass = dvmObject.getObjectType();
                    return dvmClass.hashCode();
                }
            }
        });

        Pointer _IsInstanceOf = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("IsInstanceOf object=" + object + ", clazz=" + clazz + ", dvmObject=" + dvmObject + ", dvmClass=" + dvmClass);
                }
                if (dvmObject == null || dvmClass == null) {
                    throw new BackendException();
                }
                boolean flag = dvmObject.isInstanceOf(dvmClass);
                return flag ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _GetMethodID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer methodName = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    return dvmClass.getMethodID(name, args);
                }
            }
        });

        Pointer _CallObjectMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> ret = dvmMethod.callObjectMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this));
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethod(%s, %s%s => %s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, dvmMethod.args, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return addObject(ret, false);
                }
            }
        });

        Pointer _CallObjectMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass + ", jmethodID=" + jmethodID);
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callObjectMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), obj, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return addObject(obj, false);
                }
            }
        });

        Pointer _CallBooleanMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmMethod.callBooleanMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this));
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethod(%s, %s%s => %s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, dvmMethod.args, ret == VM.JNI_TRUE, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallBooleanMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    int ret = dvmMethod.callBooleanMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret == JNI_TRUE, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallBooleanMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer jvalue = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodA object=" + object + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    int ret = dvmMethod.callBooleanMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethodA(%s, %s(%s) => %s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, vaList.formatArgs(), ret == JNI_TRUE, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallIntMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmMethod.callIntMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this));
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethod(%s, %s%s => 0x%x) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, dvmMethod.args, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallIntMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    int ret = dvmMethod.callIntMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallLongMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm64RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallLongMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    long ret = dvmMethod.callLongMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallLongMethodV(%s, %s(%s) => 0x%xL) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallFloatMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallFloatMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    float ret = dvmMethod.callFloatMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallFloatMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _CallVoidMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethod(%s, %s%s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, dvmMethod.args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    dvmMethod.callVoidMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this));
                    return 0;
                }
            }
        });

        Pointer _CallVoidMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    dvmMethod.callVoidMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethodV(%s, %s(%s)) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, vaList.formatArgs(), UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return 0;
                }
            }
        });

        Pointer _GetFieldID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer fieldName = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    return dvmClass.getFieldID(name, args);
                }
            }
        });

        Pointer _GetObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmField.getObjectField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetObjectField(%s, %s %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, dvmField.fieldType, obj, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetBooleanField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getBooleanField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetBooleanField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, ret == JNI_TRUE, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _GetIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getIntField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetIntField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _GetLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetLongField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    long ret = dvmField.getLongField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetLongField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _GetFloatField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetFloatField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    float ret = dvmField.getFloatField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetFloatField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _SetObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer value = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("SetObjectField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = getObject(value.toIntPeer());
                    dvmField.setObjectField(dvmObject, obj);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetObjectField(%s, %s %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, dvmField.fieldType, obj, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                }
                return 0;
            }
        });

        Pointer _SetBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetBooleanField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    boolean flag = value == JNI_TRUE;
                    dvmField.setBooleanField(dvmObject, flag);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetBooleanField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, flag, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                }
                return 0;
            }
        });

        Pointer _SetIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetIntField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setIntField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetIntField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, value, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                }
                return 0;
            }
        });

        Pointer _SetLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                long value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetLongField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setLongField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetLongField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, value, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                }
                return 0;
            }
        });

        Pointer _SetDoubleField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putLong(context.getLongArg(3));
                buffer.flip();
                double value = buffer.getDouble();
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setDoubleField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetDoubleField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, value, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                }
                return 0;
            }
        });

        Pointer _GetStaticMethodID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer methodName = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    return dvmClass.getStaticMethodID(name, args);
                }
            }
        });

        Pointer _CallStaticObjectMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethod(%s, %s%s) was called from %s%n", dvmClass, dvmMethod.methodName, dvmMethod.args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return addObject(dvmMethod.callStaticObjectMethod(ArmVarArg.create(emulator, DalvikVM64.this)), false);
                }
            }
        });

        Pointer _CallStaticObjectMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callStaticObjectMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethodV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return addObject(obj, false);
                }
            }
        });

        Pointer _CallStaticBooleanMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethod(%s, %s%s) was called from %s%n", dvmClass, dvmMethod.methodName, dvmMethod.args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return dvmMethod.CallStaticBooleanMethod(ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _CallStaticBooleanMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    int ret = dvmMethod.callStaticBooleanMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethodV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret == JNI_TRUE, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallStaticIntMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticIntMethod(%s, %s%s) was called from %s%n", dvmClass, dvmMethod.methodName, dvmMethod.args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return dvmMethod.callStaticIntMethod(ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _CallStaticIntMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    int ret = dvmMethod.callStaticIntMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticIntMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _CallStaticLongMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    long ret = dvmMethod.callStaticLongMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticLongMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X1, (int) (ret >> 32));
                    return (ret & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticFloatMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticFloatMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    float ret = dvmMethod.callStaticFloatMethod(ArmVarArg.create(emulator, DalvikVM64.this));
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticFloatMethod(%s, %s%s) => %s was called from %s%n", dvmClass, dvmMethod.methodName, dvmMethod.args, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _CallStaticVoidMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethod(%s, %s%s) was called from %s%n", dvmClass, dvmMethod.methodName, dvmMethod.args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    dvmMethod.callStaticVoidMethod(ArmVarArg.create(emulator, DalvikVM64.this));
                    return 0;
                }
            }
        });

        Pointer _CallStaticVoidMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jmethodID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnidbgPointer va_list = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    dvmMethod.callStaticVoidMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethodV(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return 0;
                }
            }
        });

        Pointer _GetStaticFieldID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer fieldName = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    return dvmClass.getStaticFieldID(name, args);
                }
            }
        });

        Pointer _GetStaticObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticObjectField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmField.getStaticObjectField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticObjectField(%s, %s %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, dvmField.fieldType, obj, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetStaticBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticBooleanField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    boolean ret = dvmField.getStaticBooleanField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticBooleanField(%s, %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret ? VM.JNI_TRUE : VM.JNI_FALSE;
                }
            }
        });

        Pointer _GetStaticIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticIntField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getStaticIntField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticIntField(%s, %s => 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _GetStaticLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Arm64RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getXPointer(1);
                UnidbgPointer jfieldID = context.getXPointer(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticLongField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    long ret = dvmField.getStaticLongField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticLongField(%s, %s => 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, ret, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    return ret;
                }
            }
        });

        Pointer _SetStaticIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticIntField clazz=" + clazz + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticIntField(%s, %s, 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, value, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    dvmField.setStaticIntField(value);
                }
                return 0;
            }
        });

        Pointer _SetStaticLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnidbgPointer jfieldID = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                long value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticLongField clazz=" + clazz + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticLongField(%s, %s, 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, value, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                    }
                    dvmField.setStaticLongField(value);
                }
                return 0;
            }
        });

        Pointer _GetStringUTFLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                DvmObject<?> string = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFLength string=" + string + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                String value = (String) string.getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUTFLength(%s) was called from %s%n", string, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                return data.length;
            }
        });

        Pointer _GetStringUTFChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                StringObject string = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                Pointer isCopy = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUtfChars(%s) was called from %s%n", string, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                UnidbgPointer pointer = string.allocateMemoryBlock(emulator, data.length);
                pointer.write(0, data, 0, data.length);
                return pointer.toIntPeer();
            }
        });

        Pointer _ReleaseStringUTFChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                StringObject string = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                Pointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (verbose) {
                    System.out.printf("JNIEnv->ReleaseStringUTFChars(%s) was called from %s%n", string, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0));
                }
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringUTFChars string=" + string + ", pointer=" + pointer + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                string.freeMemoryBlock(pointer);
                return 0;
            }
        });

        Pointer _GetArrayLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Array<?> array = getObject(pointer.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetArrayLength array=" + array);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->GetArrayLength(%s => %s) was called from %s%n", array, array.length(), UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                return array.length();
            }
        });

        Pointer _NewObjectArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                UnidbgPointer elementClass = context.getPointerArg(2);
                UnidbgPointer initialElement = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectArray size=" + size + ", elementClass=" + elementClass + ", initialElement=" + initialElement);
                }
                DvmClass dvmClass = classMap.get(elementClass.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException("elementClass=" + elementClass);
                }

                DvmObject<?> obj = size == 0 ? null : initialElement == null ? null : getObject(initialElement.toIntPeer());
                DvmObject<?>[] array = new DvmObject[size];
                for (int i = 0; i < size; i++) {
                    array[i] = obj;
                }

                return addObject(new ArrayObject(array), false);
            }
        });

        Pointer _GetObjectArrayElement = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                ArrayObject array = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                int index = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectArrayElement array=" + array + ", index=" + index);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->GetObjectArrayElement(%s, %d) was called from %s%n", array, index, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                return addObject(array.getValue()[index], false);
            }
        });

        Pointer _SetObjectArrayElement = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Arm64RegisterContext context = emulator.getContext();
                ArrayObject array = getObject(context.getXPointer(1).toIntPeer());
                int index = context.getXInt(2);
                UnidbgPointer element = context.getXPointer(3);
                DvmObject<?> obj = element == null ? null : getObject(element.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("setObjectArrayElement array=" + array + ", index=" + index + ", obj=" + obj);
                }
                DvmObject<?>[] objs = array.getValue();
                objs[index] = obj;
                return 0;
            }
        });

        Pointer _NewByteArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                int size = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewByteArray size=" + size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewByteArray(%d) was called from %s%n", size, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                return addObject(new ByteArray(DalvikVM64.this, new byte[size]), false);
            }
        });

        Pointer _NewIntArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                int size = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewIntArray size=" + size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewIntArray(%d) was called from %s%n", size, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                return addObject(new IntArray(DalvikVM64.this, new int[size]), false);
            }
        });

        Pointer _NewDoubleArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                int size = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("_NewDoubleArray size=" + size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewDoubleArray(%d) was called from %s%n", size, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                return addObject(new DoubleArray(DalvikVM64.this, new double[size]), false);
            }
        });

        Pointer _GetByteArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer arrayPointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer isCopy = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetByteArrayElements arrayPointer=" + arrayPointer + ", isCopy=" + isCopy);
                }
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                ByteArray array = getObject(arrayPointer.toIntPeer());
                return array._GetArrayCritical(emulator, isCopy).toIntPeer();
            }
        });

        Pointer _GetIntArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                IntArray array = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                Pointer isCopy = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntArrayElements array=" + array + ", isCopy=" + isCopy);
                }
                return array._GetArrayCritical(emulator, isCopy).peer;
            }
        });

        Pointer _GetStringLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                DvmObject<?> string = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringLength string=" + string + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                String value = (String) string.getValue();
                return value.length();
            }
        });

        Pointer _GetStringChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                StringObject string = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                Pointer isCopy = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                byte[] bytes = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                UnidbgPointer pointer = string.allocateMemoryBlock(emulator, data.length);
                pointer.write(0, data, 0, data.length);
                return pointer.toIntPeer();
            }
        });

        Pointer _ReleaseStringChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                StringObject string = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                Pointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringChars string=" + string + ", pointer=" + pointer + ", lr=" + UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                string.freeMemoryBlock(pointer);
                return 0;
            }
        });

        Pointer _NewStringUTF = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Pointer bytes = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (bytes == null) {
                    return VM.JNI_NULL;
                }

                String string = bytes.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("NewStringUTF bytes=" + bytes + ", string=" + string);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewStringUTF(\"%s\") was called from %s%n", string, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                return addObject(new StringObject(DalvikVM64.this, string), false);
            }
        });

        Pointer _ReleaseByteArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer arrayPointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int mode = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements arrayPointer=" + arrayPointer + ", pointer=" + pointer + ", mode=" + mode);
                }
                ByteArray array = getObject(arrayPointer.toIntPeer());
                array._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseIntArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                IntArray array = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                Pointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int mode = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseIntArrayElements array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                array._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _GetByteArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Backend backend = emulator.getBackend();
                ByteArray array = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                int start = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
                int length = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                Pointer buf = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                if (verbose) {
                    System.out.printf("JNIEnv->GetByteArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] data = Arrays.copyOfRange(array.value, start, start + length);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "GetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _GetShortArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                ShortArray array = getObject(context.getPointerArg(1).toIntPeer());
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                if (verbose) {
                    System.out.printf("JNIEnv->GetShortArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                short[] data = Arrays.copyOfRange(array.value, start, start + length);
                if (log.isDebugEnabled()) {
                    log.debug("GetShortArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _GetDoubleArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                DoubleArray array = getObject(context.getPointerArg(1).toIntPeer());
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                if (verbose) {
                    System.out.printf("JNIEnv->GetDoubleArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                double[] data = Arrays.copyOfRange(array.value, start, start + length);
                if (log.isDebugEnabled()) {
                    log.debug("GetDoubleArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _SetByteArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Backend backend = emulator.getBackend();
                ByteArray array = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                int start = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
                int len = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                Pointer buf = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                if (verbose) {
                    System.out.printf("JNIEnv->SetByteArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, len, buf, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] data = buf.getByteArray(0, len);
                if (log.isDebugEnabled()) {
                    if (data.length > 1024) {
                        Inspector.inspect(Arrays.copyOf(data, 1024), "SetByteArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                    } else {
                        Inspector.inspect(data, "SetByteArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                    }
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _SetIntArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Backend backend = emulator.getBackend();
                IntArray array = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                int start = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
                int len = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                Pointer buf = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                int[] data = buf.getIntArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _SetDoubleArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Backend backend = emulator.getBackend();
                DoubleArray array = getObject(UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toIntPeer());
                int start = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
                int len = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                Pointer buf = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                double[] data = buf.getDoubleArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _RegisterNatives = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer clazz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer methods = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int nMethods = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("RegisterNatives dvmClass=" + dvmClass + ", methods=" + methods + ", nMethods=" + nMethods);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->RegisterNatives(%s, %s, %d) was called from %s%n", dvmClass.getClassName(), methods, nMethods, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                for (int i = 0; i < nMethods; i++) {
                    Pointer method = methods.share((long) i * emulator.getPointerSize() * 3);
                    Pointer name = method.getPointer(0);
                    Pointer signature = method.getPointer(emulator.getPointerSize());
                    Pointer fnPtr = method.getPointer(emulator.getPointerSize() * 2L);
                    String methodName = name.getString(0);
                    String signatureValue = signature.getString(0);
                    if (log.isDebugEnabled()) {
                        log.debug("RegisterNatives dvmClass=" + dvmClass + ", name=" + methodName + ", signature=" + signatureValue + ", fnPtr=" + fnPtr);
                    }
                    dvmClass.nativesMap.put(methodName + signatureValue, (UnidbgPointer) fnPtr);

                    if (verbose) {
                        System.out.printf("RegisterNative(%s, %s%s, %s)%n", dvmClass.getClassName(), methodName, signatureValue, fnPtr);
                    }
                }
                return JNI_OK;
            }
        });

        Pointer _GetJavaVM = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer vm = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (log.isDebugEnabled()) {
                    log.debug("GetJavaVM vm=" + vm);
                }
                vm.setPointer(0, _JavaVM);
                return JNI_OK;
            }
        });

        Pointer _NewWeakGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewWeakGlobalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                addObject(dvmObject, true);
                return object.toIntPeer();
            }
        });

        Pointer _ExceptionCheck = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionCheck throwable=" + throwable);
                }
                return throwable == null ? JNI_FALSE : JNI_TRUE;
            }
        });

        Pointer _GetObjectRefType = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer object = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject<?> dvmGlobalObject = globalObjectMap.get(object.toIntPeer());
                DvmObject<?> dvmLocalObject = localObjectMap.get(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectRefType object=" + object + ", dvmGlobalObject=" + dvmGlobalObject + ", dvmLocalObject=" + dvmLocalObject);
                }
                if (dvmGlobalObject != null) {
                    return JNIGlobalRefType;
                } else if(dvmLocalObject != null) {
                    return JNILocalRefType;
                } else {
                    return JNIInvalidRefType;
                }
            }
        });

        final UnidbgPointer impl = svcMemory.allocate(0xE9 * emulator.getPointerSize(), "JNIEnv.impl");
        for (int i = 0; i < 0xE9 * emulator.getPointerSize(); i += emulator.getPointerSize()) {
            impl.setLong(i, i);
        }
        impl.setPointer(0x30, _FindClass);
        impl.setPointer(0x48, _ToReflectedMethod);
        impl.setPointer(0x68, _Throw);
        impl.setPointer(0x78, _ExceptionOccurred);
        impl.setPointer(0x88, _ExceptionClear);
        impl.setPointer(0x98, _PushLocalFrame);
        impl.setPointer(0xA0, _PopLocalFrame);
        impl.setPointer(0xa8, _NewGlobalRef);
        impl.setPointer(0xB0, _DeleteGlobalRef);
        impl.setPointer(0xB8, _DeleteLocalRef);
        impl.setPointer(0xC0, _IsSameObject);
        impl.setPointer(0xC8, _NewLocalRef);
        impl.setPointer(0xd0, _EnsureLocalCapacity);
        impl.setPointer(0xE0, _NewObject);
        impl.setPointer(0xE8, _NewObjectV);
        impl.setPointer(0xF8, _GetObjectClass);
        impl.setPointer(0x100, _IsInstanceOf);
        impl.setPointer(0x108, _GetMethodID);
        impl.setPointer(0x110, _CallObjectMethod);
        impl.setPointer(0x118, _CallObjectMethodV);
        impl.setPointer(0x128, _CallBooleanMethod);
        impl.setPointer(0x130, _CallBooleanMethodV);
        impl.setPointer(0x138, _CallBooleanMethodA);
        impl.setPointer(0x188, _CallIntMethod);
        impl.setPointer(0x190, _CallIntMethodV);
        impl.setPointer(0x1a8, _CallLongMethodV);
        impl.setPointer(0x1c0, _CallFloatMethodV);
        impl.setPointer(0x1e8, _CallVoidMethod);
        impl.setPointer(0x1f0, _CallVoidMethodV);
        impl.setPointer(0x2f0, _GetFieldID);
        impl.setPointer(0x2F8, _GetObjectField);
        impl.setPointer(0x300, _GetBooleanField);
        impl.setPointer(0x320, _GetIntField);
        impl.setPointer(0x328, _GetLongField);
        impl.setPointer(0x330, _GetFloatField);
        impl.setPointer(0x340, _SetObjectField);
        impl.setPointer(0x348, _SetBooleanField);
        impl.setPointer(0x368, _SetIntField);
        impl.setPointer(0x370, _SetLongField);
        impl.setPointer(0x380, _SetDoubleField);
        impl.setPointer(0x388, _GetStaticMethodID);
        impl.setPointer(0x390, _CallStaticObjectMethod);
        impl.setPointer(0x398, _CallStaticObjectMethodV);
        impl.setPointer(0x3A8, _CallStaticBooleanMethod);
        impl.setPointer(0x3B0, _CallStaticBooleanMethodV);
        impl.setPointer(0x408, _CallStaticIntMethod);
        impl.setPointer(0x410, _CallStaticIntMethodV);
        impl.setPointer(0x428, _CallStaticLongMethodV);
        impl.setPointer(0x438, _CallStaticFloatMethod);
        impl.setPointer(0x468, _CallStaticVoidMethod);
        impl.setPointer(0x470, _CallStaticVoidMethodV);
        impl.setPointer(0x480, _GetStaticFieldID);
        impl.setPointer(0x488, _GetStaticObjectField);
        impl.setPointer(0x490, _GetStaticBooleanField);
        impl.setPointer(0x4B0, _GetStaticIntField);
        impl.setPointer(0x4B8, _GetStaticLongField);
        impl.setPointer(0x4f8, _SetStaticIntField);
        impl.setPointer(0x500, _SetStaticLongField);
        impl.setPointer(0x520, _GetStringLength);
        impl.setPointer(0x528, _GetStringChars);
        impl.setPointer(0x530, _ReleaseStringChars);
        impl.setPointer(0x538, _NewStringUTF);
        impl.setPointer(0x540, _GetStringUTFLength);
        impl.setPointer(0x548, _GetStringUTFChars);
        impl.setPointer(0x550, _ReleaseStringUTFChars);
        impl.setPointer(0x558, _GetArrayLength);
        impl.setPointer(0x560, _NewObjectArray);
        impl.setPointer(0x568, _GetObjectArrayElement);
        impl.setPointer(0x570, _SetObjectArrayElement);
        impl.setPointer(0x580, _NewByteArray);
        impl.setPointer(0x598, _NewIntArray);
        impl.setPointer(0x5b0, _NewDoubleArray);
        impl.setPointer(0x5c0, _GetByteArrayElements);
        impl.setPointer(0x5d8, _GetIntArrayElements);
        impl.setPointer(0x600, _ReleaseByteArrayElements);
        impl.setPointer(0x618, _ReleaseIntArrayElements);
        impl.setPointer(0x640, _GetByteArrayRegion);
        impl.setPointer(0x650, _GetShortArrayRegion);
        impl.setPointer(0x670, _GetDoubleArrayRegion);
        impl.setPointer(0x680, _SetByteArrayRegion);
        impl.setPointer(0x698, _SetIntArrayRegion);
        impl.setPointer(0x6B0, _SetDoubleArrayRegion);
        impl.setPointer(0x6B8, _RegisterNatives);
        impl.setPointer(0x6D8, _GetJavaVM);
        impl.setPointer(0x710, _NewWeakGlobalRef);
        impl.setPointer(0x720, _ExceptionCheck);
        impl.setPointer(0x740, _GetObjectRefType);

        _JNIEnv = svcMemory.allocate(emulator.getPointerSize(), "_JNIEnv");
        _JNIEnv.setPointer(0, impl);

        UnidbgPointer _AttachCurrentThread = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Pointer vm = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                Pointer env = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer args = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2); // JavaVMAttachArgs*
                if (log.isDebugEnabled()) {
                    log.debug("AttachCurrentThread vm=" + vm + ", env=" + env.getPointer(0) + ", args=" + args);
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnidbgPointer _GetEnv = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Pointer vm = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                Pointer env = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                int version = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetEnv vm=" + vm + ", env=" + env.getPointer(0) + ", version=0x" + Integer.toHexString(version));
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
            log.debug("_JavaVM=" + _JavaVM + ", _JNIInvokeInterface=" + _JNIInvokeInterface + ", _JNIEnv=" + _JNIEnv);
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
        byte[] soData = apk.getFileData("lib/arm64-v8a/" + soName);
        if (soData != null) {
            if (log.isDebugEnabled()) {
                log.debug("resolve arm64-v8a library: " + soName);
            }
            return soData;
        } else {
            return null;
        }
    }
}
