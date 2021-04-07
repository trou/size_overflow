CC := gcc-9
CXX := g++-9
GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)
PLUGIN_FLAGS := -I$(GCCPLUGINS_DIR)/include -I$(GCCPLUGINS_DIR)/include/c-family #-Wno-unused-parameter -Wno-unused-variable #-fdump-passes
DESTDIR :=
LDFLAGS :=
PROG := size_overflow_plugin.so
RM := rm

CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
	else if [ -x /bin/bash ]; then echo /bin/bash; \
	else echo sh; fi ; fi)

PLUGINCC := $(shell $(CONFIG_SHELL) gcc-plugin.sh "$(CC)" "$(CXX)" "$(CC)")

ifeq ($(PLUGINCC),$(CC))
PLUGIN_FLAGS += -std=gnu99 -O0
else
PLUGIN_FLAGS += -std=gnu++98 -fno-rtti -Wno-narrowing -Og
endif

PLUGIN_FLAGS += -fPIC -shared -ggdb -Wall -W -fvisibility=hidden

all: $(PROG)

$(PROG): insert_size_overflow_asm.c intentional_overflow.c size_overflow_misc.c remove_unnecessary_dup.c size_overflow_debug.c size_overflow_ipa.c size_overflow_plugin.c size_overflow_plugin_hash.c size_overflow_transform.c size_overflow_transform_core.c
	$(PLUGINCC) $(PLUGIN_FLAGS) -o $@ $^

run: $(PROG)
	$(CC) -fplugin=$(CURDIR)/$(PROG) test.c -o test -O2 -fplugin-arg-size_overflow_plugin-check-fns -fdump-tree-all -fdump-ipa-all

clean:
	$(RM) -f $(PROG) test test.c.* test.ltrans0.* test.wpa.* test_*.c.* test_*
