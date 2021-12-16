LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := signal
LOCAL_SRC_FILES := signal.c
LOCAL_MODULE_PATH += $(LOCAL_PATH)
include $(BUILD_EXECUTABLE)
