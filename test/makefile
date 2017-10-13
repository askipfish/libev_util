#######################################
#  cmd
GCC		= 	g++
RM		=	rm
CP		=   cp


######################################
# cflags
INCLUDE_DIR		:= -I.
INCLUDE_DIR     += -I../include


# -pg
CFLAGS 	:= $(INCLUDE_DIR) -g -DLOG_INFO -static


######################################
#  dflags
LIB_DIR		:= -L. 
LIB_DIR     += -L../lib

LD_FLAGS    := -lpthread -lev_util -levent -lm -lz -lrt

#######################################
#  make
	
%.o: %.cpp 
	g++ $(CFLAGS) -c $< -o $@ 


all:  test_ev


test_ev: test_ev.o
	g++ $(LIB_DIR) -o test_ev test_ev.o $(LD_FLAGS)


clean:
	rm *.o test_ev


