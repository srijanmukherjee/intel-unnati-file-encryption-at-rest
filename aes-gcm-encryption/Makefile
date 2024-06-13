CPP=g++
CFLAGS=-Wall
LDFLAGS=`pkg-config --libs openssl`

enc: main.cpp
	$(CPP) $(CFLAGS) $(LDFLAGS) -o enc main.cpp