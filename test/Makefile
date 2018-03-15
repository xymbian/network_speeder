EXECUTABLE := test

CC := gcc
CFLAGS := -Wall -O2

SOURCE := $(wildcard *.c)

OBJS := $(patsubst %.c, %.o, $(SOURCE))

all : $(EXECUTABLE)
$(EXECUTABLE) : $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) -o $(EXECUTABLE)

.PHONY : clean

clean :
	@rm -f $(EXECUTABLE) $(OBJS) *.o
