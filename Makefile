main: main.o
	gcc main.o -o main -L/usr/local/lib64/ -lssl -lcrypto
#	gcc -I/usr/local/include/ -lopenssl main.o -o main
#	gcc main.o -o main -I/usr/local/include/ -L/usr/local/lib64/ -lopenssl

main.o: main.c
	gcc -c main.c -std=gnu11

clean:
	rm main main.o
