## VARIABLES
VERSION=`cat VERSION`

dev:
	@mkdir -p bin/x64
	@GOOS=linux GOARCH=amd64 go build -o bin/x64/chef-guard

deploy:
	@mkdir -p bin/x64
	@GOOS=linux GOARCH=amd64 go build -o bin/x64/chef-guard
	scp bin/x64/chef-guard sbpa2chef-infra02:~/
	ssh -t sbpa1chef-infra01 "sudo mv ~/chef-guard /opt/chef-guard/chef-guard"
	ssh -t sbpa1chef-infra01 "sudo systemctl restart chef-guard"

release:
	@mkdir -p bin/x86
	@GOOS=linux GOARCH=386 go build -o bin/x86/chef-guard
	tar zcvf chef-guard-v$(VERSION)-linux-x86.tar.gz -C examples . -C ../bin/x86 .
	@mkdir -p bin/x64
	@GOOS=linux GOARCH=amd64 go build -o bin/x64/chef-guard
	tar zcvf chef-guard-v$(VERSION)-linux-x64.tar.gz -C examples . -C ../bin/x64 .

