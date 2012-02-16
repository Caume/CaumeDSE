CC=gcc
CFLAGS=-c -fno-strict-aliasing -Wall -Wextra -pipe -pg -g
DEFINES=-DDEBUG -DERROR_LOG -DPURIFY -DSQLITE_SECURE_DELETE
LDOPTS=$(shell perl -MExtUtils::Embed -e ldopts)
CCOPTS=$(shell perl -MExtUtils::Embed -e ccopts)
DYNLDR=$(shell find / -iname "dynaloader.a")
LDFLAGS=-lcrypto -lpthread -lperl -lnsl -ldl -lm -lcrypt -lutil -lc -lmicrohttpd -L/usr/local/lib
SOURCES=main.c crypto.c db.c engine_admin.c engine_interface.c filehandling.c function_tests.c perl_interpreter.c strhandling.c xs_init.c webservice_interface.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=CaumeDSE

all: $(SOURCES) sqlite3.o $(EXECUTABLE)
	
$(EXECUTABLE): xs_init.o sqlite3.o $(OBJECTS)
#	$(CC) -pg $(LDFLAGS) $(LDOPTS) $(OBJECTS) DynaLoader.o sqlite3.o -o $@
	$(CC) -pg $(LDFLAGS) $(LDOPTS) $(OBJECTS) sqlite3.o -o $@
xs_init.o: xs_init.c
	perl -MExtUtils::Embed -e xsinit -- -o - >xs_init.c
#	ar xv $(DYNLDR)
	$(CC) $(CFLAGS) $(DEFINES) $(CCOPTS) $< -o $@

sqlite3.o: sqlite/sqlite3.c sqlite/sqlite3.h
	$(CC) $(CFLAGS) $(CCOPTS) sqlite/sqlite3.c sqlite/sqlite3.h 

.c.o:
	$(CC) $(CFLAGS) $(DEFINES) $(CCOPTS) $< -o $@

clean:
	rm *.o
	rm CaumeDSE

install:
	if [ ! -d /opt ]; \
	then \
		mkdir /opt; \
	fi
	if [ ! -d /opt/cdse ]; \
	then \
		mkdir /opt/cdse/; \
	fi
	if [ ! -d /opt/cdse/secureTmp ]; \
        then \
		mkdir /opt/cdse/secureTmp; \
		chmod 600 /opt/cdse/secureTmp/; \
	fi
	cp favicon.ico /opt/cdse/
	cp TEST/testCertAuth/server.key /opt/cdse
	cp TEST/testCertAuth/server.pem /opt/cdse
	cp TEST/testCertAuth/ca.pem /opt/cdse
	cp -R TEST/testfiles /opt/cdse/
	-mkdir /opt/cdse/bin
	cp CumulusEngine /opt/cdse/bin
	chmod 700 -R /opt/cdse/bin

