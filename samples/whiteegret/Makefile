# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# List of programs to build
hostprogs-$(CONFIG_SAMPLE_WHITEEGRET) := sample-we-user

sample-we-user-objs := main.o checkwl.o

HOSTCFLAGS += -Wall
HOSTCFLAGS += -I/usr/local/include
HOSTCFLAGS += -I$(srctree)/security/whiteegret

# Tell kbuild to always build the programs
always := $(hostprogs-y)
