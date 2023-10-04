CC = gcc
LIB = -lnsl
DNSCLT = dnsclient

build: clean $(DNSCLT)

$(DNSCLT): $(DNSCLT).c
	$(CC) $(DNSCLT).c -o $(DNSCLT) $(LIB)

clean:
	rm -f *.log *.o $(DNSCLT)

