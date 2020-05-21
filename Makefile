CFLAGS += -std=c99 -O0

PROGRAM = spectrev2
SOURCE  = spectrev2.c

all: $(PROGRAM)

$(PROGRAM): $(SOURCE) ; $(CC) $(CFLAGS) -o $(PROGRAM) $(SOURCE)

clean: ; rm -f $(PROGRAM)
