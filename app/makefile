IDIR=appy
IDIR2=appy-app
CC=emcc
CFLAGS=-I$(IDIR) -I$(IDIR2) -O3 -Wno-shift-negative-value

ODIR=bin
LDIR=

LIBS=

_DEPS=
DEPS=$(patsubst %,$(ODIR)/%,$(_DEPS))

_OBJ=Raycast.o Splat.o Skel3D.o nanojpeg.o App.o AppAudio.o AppGraph.o Noise.o MoreMath.o Common.o
OBJ=$(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(IDIR)/%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(IDIR2)/%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/app.html: $(OBJ) $(DEPS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) -s FETCH=1

.PHONY: clean

clean:
	rm -f $(ODIR)/*
