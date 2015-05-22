default: test

test: generate
	go test ./...

generate:
	go generate ./...
