socket : socket.o build_packet.o
	gcc -o socket socket.o build_packet.o
socket.o : socket.c socket_head.h
	gcc -c socket.c
build_packet.o : build_packet.c socket_head.h
	gcc -c build_packet.c
clean :
	rm build_packet.o socket.o socket
