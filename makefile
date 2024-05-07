APP_NAME=meeda
GIT_COMMIT=$(shell git rev-parse --short HEAD)
BUILD_TIME=$(shell TZ=Asia/Shanghai date +'%Y-%m-%d.%H:%M:%S%Z')
BUILD_FLAGS=-ldflags "-X 'github.com/memoio/meeda-node/cmd.BuildFlag=$(GIT_COMMIT)+$(BUILD_TIME)'"

all: clean build

clean:
	rm -f ${APP_NAME}

build:
	go build $(BUILD_FLAGS) -o ${APP_NAME}

install:
	mv ${APP_NAME} /usr/local/bin
	
.PHONY: all clean build