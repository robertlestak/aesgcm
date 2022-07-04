bin: bin/aesgcm_darwin bin/aesgcm_linux bin/aesgcm_windows

bin/aesgcm_darwin:
	mkdir -p bin
	GOOS=darwin go build -o bin/aesgcm_darwin

bin/aesgcm_linux:
	mkdir -p bin
	GOOS=linux go build -o bin/aesgcm_linux

bin/aesgcm_windows:
	mkdir -p bin
	GOOS=windows go build -o bin/aesgcm_windows