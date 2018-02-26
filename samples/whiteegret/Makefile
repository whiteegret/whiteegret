# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# List of programs to build
hostprogs-$(CONFIG_SAMPLE_WHITEEGRET) := sample-we-user

sample-we-user-objs := main.o checkwl.o
ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
sample-we-user-objs += gennl.o
endif

HOSTCFLAGS += -Wall
HOSTCFLAGS += -I/usr/local/include
HOSTCFLAGS += -I$(srctree)/security/whiteegret
ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
HOSTCFLAGS += -I$(srctree)/drivers/security/whiteegret
HOSTCFLAGS += -DCONFIG_SECURITY_WHITEEGRET_DRIVER
endif

ifndef CONFIG_SECURITY_WHITEEGRET_DRIVER
HOSTLOADLIBES_sample-we-user += -lnl
endif

# Tell kbuild to always build the programs
always := $(hostprogs-y)
