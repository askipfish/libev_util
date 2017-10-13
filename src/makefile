#######################################
#  cmd
GCC		= 	g++
RM		=	rm
CP		=   cp


#######################################
#% 路径
OUTPUT_DIR	=	../objs
RELEASE_DIR = ../lib



######################################
# cflags
INCLUDE_DIR		:= -I.
INCLUDE_DIR     += -I../thirdparty/libevent/include


# -pg
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS		:= -g -O0
else
	CFLAGS		:= -O2
endif
CFLAGS 	+= $(INCLUDE_DIR) -DLOG_INFO -static


######################################
#  dflags
LIB_DIR		:= -L. 
LIB_DIR     += -L../thirdparty/libevent/lib

LD_FLAGS    := -lpthread -levent -lm -lz -lrt

#######################################
#  make
OBJS 		=   $(OUTPUT_DIR)/yg_log.o 		    \
				$(OUTPUT_DIR)/yg_net.o 			\
				$(OUTPUT_DIR)/yg_evsrv.o 		
				
	
$(OUTPUT_DIR)/%.o: %.cpp
	g++ $(CFLAGS) -c $< -o $@

$(OUTPUT_DIR)/%.o: %.c
	gcc $(CFLAGS) -c $< -o $@



$(OUTPUT_DIR)/%.d: %.cpp 
	@set -e; rm -f $@;\
	g++ -MM $(CFLAGS) $< > $@.tmp; \
	sed 's,\($*\)\.o[ :],$(OUTPUT_DIR)/\1.o $@ :,g' < $@.tmp > $@;\
	rm -f $@.tmp

$(OUTPUT_DIR)/%.d: %.c
	@set -e; rm -f $@; \
	gcc -MM $(CFLAGS) $< > $@.tmp; \
	sed 's,\($*\)\.o[ :],$(OUTPUT_DIR)/\1.o $@ :,g' < $@.tmp > $@; \
	rm -f $@.tmp



all: libev_util.a


libev_util.a: $(OBJS)
	ar rcs $(OUTPUT_DIR)/libev_util.a $(OBJS)



######################################
#  make install
install:
	cp *.h ../include
	cp $(OUTPUT_DIR)/lib*.a ../lib
	cp ../thirdparty/libevent/lib/lib*.a ../lib
	


#######################################
#  clean
clean:
	$(RM)  $(OUTPUT_DIR)/*.o $(OUTPUT_DIR)/*.d
	rm $(OUTPUT_DIR)/*.a

include $(patsubst %.cpp, $(OUTPUT_DIR)/%.d, $(wildcard *.cpp))
include $(patsubst %.c, $(OUTPUT_DIR)/%.d, $(wildcard *.c))


