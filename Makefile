# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o main.o server.cpp
	g++ $(PCAPPP_LIBS_DIR) -o program main.o $(PCAPPP_LIBS)
	rm main.o

# Clean Target
clean:
	rm main.o
