CXX = g++
CXXFLAGS = -g -Wall
TARGET = program
SOURCES = main.cpp DHCPReservation.cpp DHCPReservationPool.cpp
HEADERS = DHCPReservation.h DHCPReservationPool.h
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJECTS)
	rm -f *.o

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f *.o

# Build with: make -B