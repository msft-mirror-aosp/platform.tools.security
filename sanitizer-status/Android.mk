LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CFLAGS := -std=c11 -Wall -Werror -O0

LOCAL_SRC_FILES:= sanitizer-status.c

LOCAL_MODULE:= libsanitizer-status

ifneq ($(filter address,$(SANITIZE_TARGET)),)
LOCAL_CFLAGS += -DANDROID_SANITIZE_ADDRESS=1
endif

ifneq ($(filter coverage,$(SANITIZE_TARGET)),)
LOCAL_CFLAGS += -DANDROID_SANITIZE_COVERAGE=1
endif

include $(BUILD_SHARED_LIBRARY)
#==========================================================
include $(CLEAR_VARS)

LOCAL_CFLAGS := -std=c11 -Wall -Werror -O0

LOCAL_SRC_FILES:= main.c

LOCAL_MODULE:= sanitizer-status

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)

LOCAL_SHARED_LIBRARIES += libsanitizer-status

include $(BUILD_EXECUTABLE)
