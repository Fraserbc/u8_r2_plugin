# Work around 'user' r2 installation...
#prefix=/home/$$USER/bin/prefix/radare2
#exec_prefix=${prefix}
#libdir=/home/$$USER/bin/prefix/radare2/lib
#includedir=${prefix}/include
#CFLAGS=-g -fPIC -I${includedir}/libr
#ASM_LDFLAGS=-shared -L${libdir} -lr_asm
#ANAL_LDFLAGS=-shared -L${libdir} -lr_anal

# ...or use pkg-config if installed normally
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm)
ANAL_LDFLAGS=-shared $(shell pkg-config --libs r_anal)

ANAL_OBJS=anal_u8.o u8_inst.o u8_disas.o

R2_PLUGIN_PATH="/home/fraser/.local/share/radare2/plugins"#$(shell r2 -H R2_USER_PLUGINS)
LIBEXT="so"#$(shell r2 -H LIBEXT)
ANAL_LIB=anal_u8.$(LIBEXT)

all: $(ANAL_LIB) install

clean:
	rm -f $(ASM_LIB) $(ANAL_LIB) $(ASM_OBJS) $(ANAL_OBJS)


$(ANAL_LIB): $(ANAL_OBJS)
	$(CC) $(CFLAGS) $(ANAL_LDFLAGS) $(ANAL_OBJS) -o $(ANAL_LIB)

install:
	cp -f anal_u8.$(LIBEXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/anal_u8.$(LIBEXT)

test:
	r2 -a u8 ../u8dis/rom.bin

backup:
	tar cvf ../u8_r2_plugin.tar .
