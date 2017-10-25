docker run --rm -v "%GOPATH%:/go" -e GO386=387 -e GOOS=linux -e GOARCH=386 golangpcap go build -o /go/src/git.progwebtech.com/captive/capcap/cli/cli_linux_386 git.progwebtech.com/captive/capcap/cli

./capcap service -a "-i=wlan0" -a "-u=/tmp/network" -a "-c=true" install