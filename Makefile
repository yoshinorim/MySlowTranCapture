TARGET = myslowtrancapture

SRCS= local_addresses.cc my_slow_tran_capture.cc
OBJS= local_addresses.o my_slow_tran_capture.o

DEST= /usr/local/bin
CXX= g++
CXXFLAGS= -Wall -O3
LFLAGS= -Wall -O3 
LIBS= -lpcap -lboost_regex
DEBUG= -g -pg

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LFLAGS) $(OBJS) $(LIBS) -o $(TARGET)

$(TARGET).o: $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS)

clean:
	rm -f *.o $(TARGET)

install: $(TARGET)
	install -s $(TARGET) $(DEST)

