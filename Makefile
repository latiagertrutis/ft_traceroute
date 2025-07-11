.PHONY: all clean distclean test re

TARGET = ft_traceroute

SRC = $(addprefix src/,traceroute.c mod-default.c mod-icmp.c)
OBJ = $(SRC:.c=.o)
DEP = $(SRC:.c=.d)

CFLAGS = -g -Wall -Werror -Wextra

CC = gcc

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
ifdef USE_RAW_SOCKET
	sudo setcap cap_net_raw=ep $@
endif

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM -MT '$(@:.d=.o)' $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

include $(DEP)

test:
	@mkdir -p test/output
	@$(MAKE) -f test.mk -C test

clean:
	@rm -f $(OBJ) $(DEP)

re: clean
	@$(MAKE) all

distclean: clean
	@rm -f $(TARGET)
