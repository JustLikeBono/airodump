all: airodump

airodump: airodump.o main.o
	gcc -o airodump airodump.o main.o -lpcap

main.o: airodump.h main.cpp -lpcap

airodump.o: airodump.h airodump.cpp -lpcap

clean:
	rm -f airodump.*
	rm -f *.o