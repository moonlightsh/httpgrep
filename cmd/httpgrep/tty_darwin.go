package main

import "syscall"

// ioctlGetTermios 是读取终端属性的 ioctl 请求号；macOS 上是 TIOCGETA。
const ioctlGetTermios = syscall.TIOCGETA
