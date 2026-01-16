.PHONY: all clean distclean test re

TARGET = ft_traceroute

SRC = $(addprefix src/,traceroute.c mod-default.c mod-icmp.c mod-generic.c utils.c ip_utils.c probe.c)
OBJ = $(SRC:.c=.o)
DEP = $(SRC:.c=.d)

CFLAGS = -g -Wall -Werror -Wextra

CC = gcc

BEAR ?= bear --append --

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

%.o: %.c
	$(BEAR) $(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

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
