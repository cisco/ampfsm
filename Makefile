ifndef TARGET_KERNEL_VERSION
    TARGET_KERNEL_VERSION=$(shell uname -r)
endif

all:
	make -C /lib/modules/$(TARGET_KERNEL_VERSION)/build M=$(PWD) EXTRA_CFLAGS="-I$(PWD)/common/include $(EXTRA_CFLAGS)" modules

clean:
	make -C /lib/modules/$(TARGET_KERNEL_VERSION)/build M=$(PWD) clean

# Needed for Check unit test framework
check:
