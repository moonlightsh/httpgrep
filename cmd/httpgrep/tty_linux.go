package main

import "syscall"

// ioctlGetTermios 是读取终端属性的 ioctl 请求号；Linux 上是 TCGETS。
const ioctlGetTermios = syscall.TCGETS
