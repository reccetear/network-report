socket : socket.o analyse.o
	gcc -o socket socket.o analyse.o
socket.o : socket.c socket_head.h
	gcc -c socket.c
analyse.o : analyse.c socket_head.h
	gcc -c analyse.c
clean : 
	rm socket.o analyse.o socket
play :
	sudo ./socket
test :
	ping www.baidu.com
