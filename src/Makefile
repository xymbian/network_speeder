EXECUTABLE := ipv4_checksum

CC := gcc
CFLAGS := -Wall -g

SOURCE := $(wildcard *.c)

OBJS := $(patsubst %.c, %.o, $(SOURCE))

all : $(EXECUTABLE)
$(EXECUTABLE) : $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) -o $(EXECUTABLE)

.PHONY : clean

clean :
	@rm -f $(EXECUTABLE) $(OBJS) *.o
