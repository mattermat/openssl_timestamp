main: main.o
	gcc main.o -o main -I/usr/local/ssl/include -L/usr/local/ssl/lib64 -Wl,-rpath,/usr/local/lib64 -lssl -lcrypto

main.o: main.c
	gcc -c main.c -std=gnu11 -I/usr/local/ssl/include -L/usr/local/ssl/lib64

clean:
	rm main main.o
