PROCESS_NAME=kernel
IDIR =./include
SHARED_IDIR = ../shared/include
CCC ?=gcc
CC=$(CCC)
CFLAGS=-I$(IDIR) -I$(SHARED_IDIR) -g -Wall -fno-strict-aliasing -Wno-incompatible-pointer-types

ODIR=./obj
SRCDIR =./src
LIBS=-lcommons -lpthread -lreadline -lcunit -lrt -lm

SHARED_SRCDIR = ../shared/src
SHARED_ODIR = ./obj/shared

DEPS = $(wildcard $(IDIR)/*.h)

SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(patsubst $(SRCDIR)/%.c,$(ODIR)/%.o,$(SRC))

$(ODIR)/%.o: $(SRCDIR)/%.c $(ODIR) $(DEPS) $(SHARED_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	mkdir $@

$(SHARED_ODIR)/%.o: $(SHARED_SRCDIR)/%.c $(SHARED_ODIR) $(SHARED_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(SHARED_ODIR):
	mkdir $@

SHARED_DEPS = $(wildcard $(SHARED_IDIR)/*.h)

SHARED_SRC = $(wildcard $(SHARED_SRCDIR)/*.c)
SHARED_OBJ = $(patsubst $(SHARED_SRCDIR)/%.c,$(SHARED_ODIR)/%.o,$(SHARED_SRC))

$(PROCESS_NAME): $(OBJ) $(SHARED_OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ $(PROCESS_NAME) $(SHARED_ODIR)/*.o 
