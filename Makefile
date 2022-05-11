PWD := $(shell pwd) 
KVERSION := $(shell uname -r)
INCLUDE_DIR = /usr/src/linux-headers-$(KVERSION)/

CONFIG_MODULE_SIG=n
MODULE_NAME = upf

CFLAGS += -ggdb
EXTRA_CFLAGS += -Wno-misleading-indentation -Wuninitialized

obj-m := $(MODULE_NAME).o
upf-y := main.o
upf-y += dev.o
upf-y += gtp.o
upf-y += pktinfo.o
upf-y += hash.o
upf-y += seid.o
upf-y += encap.o
upf-y += genl.o
upf-y += genl_pdr.o
upf-y += genl_far.o
upf-y += genl_qer.o
upf-y += genl_bar.o
upf-y += genl_urr.o
upf-y += pdr.o
upf-y += far.o
upf-y += qer.o
upf-y += bar.o
upf-y += urr.o
upf-y += net.o
upf-y += link.o

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
