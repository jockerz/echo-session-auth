test:
	go test -v

test-coverage:
	go test -v ./... -covermode=count -coverpkg=./... -coverprofile coverage.out
	go tool cover -html coverage.out -o coverage.html

clean:
	rm coverage.html coverage.out
