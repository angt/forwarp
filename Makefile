NAME    := forwarp
CFLAGS  ?= -std=c11 -O2 -Wall -fstack-protector-strong
FLAGS   := $(CFLAGS) $(LDFLAGS) $(CPPFLAGS)

CC      ?= cc
Q       := @

ifneq ($(X),)
    H = $(X)-
    FLAGS += -static
endif

$(NAME): main.c
	$(Q)$(H)$(CC) $(FLAGS) -o $@ $^

.PHONY: clean
clean:
	$(Q)git clean -Xf
