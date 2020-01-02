PROJECT_NAME := mitosis-crypto-tests

OUTPUT_FILENAME := crypto-tests
#MAKEFILE_NAME := $(CURDIR)/$(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))
MAKEFILE_NAME := $(MAKEFILE_LIST)
MAKEFILE_DIR := $(dir $(MAKEFILE_NAME) )

TEMPLATE_PATH = ../../../components/toolchain/gcc
ifeq ($(OS),Windows_NT)
include $(TEMPLATE_PATH)/Makefile.windows
else
include $(TEMPLATE_PATH)/Makefile.posix
endif

MK := mkdir
RM := rm -rf

#echo suspend
ifeq ("$(VERBOSE)","1")
NO_ECHO :=
else
NO_ECHO := @
endif

# Toolchain commands
# CC              := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-gcc'
AS              := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-as'
AR              := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-ar' -r
# LD              := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-ld'
NM              := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-nm'
OBJDUMP         := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-objdump'
OBJCOPY         := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-objcopy'
SIZE            := '$(GNU_INSTALL_ROOT)/bin/$(GNU_PREFIX)-size'
CC 							:= gcc
LD							:= ld

#function for removing duplicates in a list
remduplicates = $(strip $(if $1,$(firstword $1) $(call remduplicates,$(filter-out $(firstword $1),$1))))

#source common to all targets
C_SOURCE_FILES += \
$(abspath ./main.c) \
$(abspath ./aes.c) \
$(abspath ../mitosis-hmac.c) \
$(abspath ../mitosis-cmac.c) \
$(abspath ../mitosis-hkdf.c) \
$(abspath ../mitosis-ckdf.c) \
$(abspath ../mitosis-aes-ctr.c) \
$(abspath ../mitosis-keys.c) \
$(abspath ../../../components/libraries/sha256/sha256.c) \

#includes common to all targets
INC_PATHS  = -I$(abspath ../)
INC_PATHS += -I$(abspath ../../../components/drivers_nrf/hal)
INC_PATHS += -I$(abspath ../../../components/libraries/sha256)
INC_PATHS += -I$(abspath ../../../components/libraries/util)
INC_PATHS += -I$(abspath ../../../components/drivers_nrf/nrf_soc_nosd)
INC_PATHS += -I$(abspath ../../../components/device)

OBJECT_DIRECTORY = _build
LISTING_DIRECTORY = $(OBJECT_DIRECTORY)
OUTPUT_BINARY_DIRECTORY = bin

BUILD_DIRECTORIES := $(sort $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY) $(LISTING_DIRECTORY) )

CFLAGS = -DUNIX
CFLAGS += -Wall -Og -g3
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable

LDFLAGS=-Wall

C_SOURCE_FILE_NAMES = $(notdir $(C_SOURCE_FILES))
C_PATHS = $(call remduplicates, $(dir $(C_SOURCE_FILES) ) )
C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_SOURCE_FILE_NAMES:.c=.o) )

vpath %.c $(C_PATHS)

OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

default: $(BUILD_DIRECTORIES) $(OBJECTS)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) -lm -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME).out

## Create build directories
$(BUILD_DIRECTORIES):
	echo $(MAKEFILE_NAME)
	$(MK) $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.c
	@echo Compiling file: $(notdir $<)
	$(NO_ECHO)$(CC) $(CFLAGS) $(INC_PATHS) -c -o $@ $<
# Link
$(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME).out: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo Linking target: $(OUTPUT_FILENAME).out
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) -lm -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME).out

clean:
	$(RM) $(BUILD_DIRECTORIES)
