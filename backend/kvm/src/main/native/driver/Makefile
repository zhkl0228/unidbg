obj-m += hcr-driver.o
SRCDIR = $(PWD)
hcr-driver-objs := hcr.o
MCFLAGS += -std=gnu11 -O3 -D_ARCH_ARM64_
ccflags-y += ${MCFLAGS}
CC += ${MCFLAGS}
KDIR := /lib/modules/$(shell uname -r)/build
KOUTPUT := $(PWD)/build
KOUTPUT_MAKEFILE := $(KOUTPUT)/Makefile
LD += -S

KBUILD_EXTRA_SYMBOLS += $(PWD)/kernel-hook-framework/src/Module.symvers

all: $(KOUTPUT_MAKEFILE)
	make -C $(KDIR) M=$(KOUTPUT) src=$(SRCDIR) modules

$(KOUTPUT):
	mkdir -p "$@"
	mkdir -p "$@"/kernel-hook

$(KOUTPUT_MAKEFILE): $(KOUTPUT)
	touch "$@"

clean:
	make -C $(KDIR) M=$(KOUTPUT) src=$(SRCDIR) clean
	$(shell rm $(KOUTPUT_MAKEFILE))
	rmdir $(KOUTPUT)/kernel-hook
	rmdir $(KOUTPUT)
