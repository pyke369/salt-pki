#!/bin/sh

# build targets
salt-pki: *.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o salt-pki
	@-strip salt-pki 2>/dev/null || true
	@-upx -9 salt-pki 2>/dev/null || true
clean:
	@rm -rf log
distclean: clean
	@rm -f salt-pki
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../salt-pki_*

# run targets
run: salt-pki
	@./salt-pki salt-pki.conf
