CC = gcc
CFLAGS = -Wall -Wextra

cliente: cliente.o md5.o
	$(CC) -o $@ $^

%.o: %.c md5.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o cliente