LDLIBS += -lpcap
CXXFLAGS += -std=c++11

all: tcp-block

tcp-block: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
