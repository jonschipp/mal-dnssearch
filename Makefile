PROG = mal-dnssearch
PREFIX = /usr/local
DEST = $(PREFIX)/$(PROG)
BIN = /usr/bin

default: install

install:
	$(info Installing mal-dnssearch to $(DEST))
	mkdir -p $(DEST)
	chmod 755 $(DEST)
	install mal-dnssearch.sh $(DEST)
	install tools/mal-dns2bro.sh $(DEST)
	ln -f -s $(DEST)/mal-dnssearch.sh $(BIN)/mal-dnssearch
	ln -f -s $(DEST)/mal-dns2bro.sh $(BIN)/mal-dns2bro

uninstall:
	$(info Uninstalling mal-dnssearch!)
	unlink $(BIN)/mal-dnssearch
	unlink $(BIN)/mal-dns2bro
	rm -fr $(DEST)
