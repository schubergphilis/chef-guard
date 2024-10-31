## VARIABLES
VERSION=`cat VERSION`

dev:
	@mkdir -p bin/x64
	@GOOS=linux GOARCH=amd64 go build -o bin/x64/chef-guard

release:
	@mkdir -p bin/x86
	@GOOS=linux GOARCH=386 go build -o bin/x86/chef-guard
	tar zcvf chef-guard-v$(VERSION)-linux-x86.tar.gz -C examples . -C ../bin/x86 .
	@mkdir -p bin/x64
	@GOOS=linux GOARCH=amd64 go build -o bin/x64/chef-guard
	tar zcvf chef-guard-v$(VERSION)-linux-x64.tar.gz -C examples . -C ../bin/x64 .

