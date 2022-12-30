# Work around 'user' r2 installation...
#prefix=/home/$$USER/bin/prefix/radare2
#exec_prefix=${prefix}
#libdir=/home/$$USER/bin/prefix/radare2/lib
#includedir=${prefix}/include
#CFLAGS=-g -fPIC -I${includedir}/libr
#ARCH_LDFLAGS=-shared -L${libdir} -lr_anal

# ...or use pkg-config if installed normally
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm)
ARCH_LDFLAGS=-shared $(shell pkg-config --libs r_anal)

ARCH_OBJS=arch_u8.o u8_inst.o u8_disas.o

R2_PLUGIN_PATH=$(shell r2 -H R2_USER_PLUGINS)
LIBEXT=$(shell r2 -H LIBEXT)
ARCH_LIB=arch_u8.$(LIBEXT)

all: $(ARCH_LIB) install

clean:
	rm -f $(ARCH_LIB) $(ARCH_OBJS)

$(ARCH_LIB): $(ARCH_OBJS)
	$(CC) $(CFLAGS) $(ARCH_LDFLAGS) $(ARCH_OBJS) -o $(ARCH_LIB)

install:
	cp -f arch_u8.$(LIBEXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/arch_u8.$(LIBEXT)