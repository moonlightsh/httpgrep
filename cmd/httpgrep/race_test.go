//go:build race

package main

// raceEnabled 为真时 TestMain 用 -race 编译被测程序，让 go test -race 也检查可执行文件本身。
const raceEnabled = true
