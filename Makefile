OUT_PATH=out/bin
BINARY_NAME=secure-files-go
DARWIN_ARM64_BIN=${OUT_PATH}/${BINARY_NAME}-darwin_arm64
LINUX_AMD64_BIN=${OUT_PATH}/${BINARY_NAME}-linux_amd64
WIN_AMD64_BIN=${OUT_PATH}/${BINARY_NAME}-win_amd64.exe

build:
	mkdir -p out/bin
	GOARCH=arm64 GOOS=darwin go build -ldflags "-s -w" -o ${DARWIN_ARM64_BIN} .
	GOARCH=amd64 GOOS=linux go build -ldflags "-s -w" -o ${LINUX_AMD64_BIN} .
	GOARCH=amd64 GOOS=windows go build -ldflags "-s -w" -o ${WIN_AMD64_BIN} .

# run: build
# 	./out/bin/${BINARY_NAME}-darwin_arm64

clean:
	go clean
	rm -rf ${DARWIN_ARM64_BIN}
	rm -rf ${LINUX_AMD64_BIN}
	rm -rf ${WIN_AMD64_BIN}

update:
	go get -u ./...
	
list:
	go list -m all