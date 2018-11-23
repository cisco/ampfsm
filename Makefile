ifndef TARGET_KERNEL_VERSION
    TARGET_KERNEL_VERSION=$(shell uname -r)
endif

all:
	make -C /lib/modules/$(TARGET_KERNEL_VERSION)/build M=$(PWD) EXTRA_CFLAGS="-I$(PWD)/common/include $(EXTRA_CFLAGS)" modules

clean:
	make -C /lib/modules/$(TARGET_KERNEL_VERSION)/build M=$(PWD) clean

sparse:
	# C=2 to run sparse on the files whether they need to be recompiled or not
	make C=2 -C /lib/modules/$(TARGET_KERNEL_VERSION)/build M=$(PWD) EXTRA_CFLAGS="-I$(PWD)/common/include $(EXTRA_CFLAGS)" modules

# Needed for Check unit test framework
check:
