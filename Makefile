CC = gcc
CFLAGS = -O0 -ggdb3 -W -Wall -std=gnu11
LDFLAGS = 
LIBS = -lssl -lcrypto

all: ecies

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

ecies: ecies.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o ecies
