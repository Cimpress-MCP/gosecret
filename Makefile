default: test

test: generate
	ln -s ${GOPATH}/src/github.com/cimpress-mcp/gosecret to ${TRAVIS_BUILD_DIR}
	go test ./...

generate:
	go generate ./...
