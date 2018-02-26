obj-$(CONFIG_SECURITY_WHITEEGRET) += whiteegret.o
whiteegret-y := init.o main.o request.o
ifdef CONFIG_SECURITY_WHITEEGRET_DRIVER
whiteegret-y += dd_com.o
else
whiteegret-y += gennl.o auth.o
endif
