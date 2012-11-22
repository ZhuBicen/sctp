all:sctpclient01 sctpserv01 sctpclient01_mul
clean:
	rm -fr sctpclient01 sctpserv01 sctpclient01_mul
sctpclient01: sctpclient01.cpp
	g++ $< -o$@ -lsctp
sctpserv01:sctpserv01.cpp
	g++ $< -o$@ -lsctp
sctpclient01_mul:sctpclient01_mul.cpp
	g++ $< -o$@ -lsctp

