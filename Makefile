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
	ln -s $(DEST)/mal-dnssearch.sh $(BIN)/mal-dnssearch

uninstall:
	$(info Uninstalling mal-dnssearch!)
	unlink $(BIN)/mal-dnssearch
	rm -fr $(DEST)
