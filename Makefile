PWD := $(shell pwd) 
KVERSION := $(shell uname -r)
INCLUDE_DIR = /usr/src/linux-headers-$(KVERSION)/

CONFIG_MODULE_SIG=n
MODULE_NAME = upf

CFLAGS += -ggdb
EXTRA_CFLAGS += -Wno-misleading-indentation -Wuninitialized

obj-m := $(MODULE_NAME).o
upf-y := main.o dev.o hash.o seid.o encap.o genl.o genl_pdr.o genl_far.o genl_qer.o pdr.o far.o qer.o net.o link.o

all:
	make -C $(INCLUDE_DIR) M=$(PWD) modules
clean:
	make -C $(INCLUDE_DIR) M=$(PWD) clean
 
install:
	cp $(MODULE_NAME).ko /lib/modules/`uname -r`/kernel/drivers/net
	depmod -a
	modprobe $(MODULE_NAME)

uninstall:
	rmmod $(MODULE_NAME)
	rm -f /lib/modules/`uname -r`/kernel/drivers/net/$(MODULE_NAME).ko
	depmod -a
