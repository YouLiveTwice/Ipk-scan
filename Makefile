output: ipk-scan.o
	g++ ipk-scan.o -o ipk-scan

ipk-scan.o: ipk-scan.cpp
	g++ -c ipk-scan.cpp

clean:
	rm *.o output