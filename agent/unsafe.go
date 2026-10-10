package main

import "unsafe"

func ptrOf(b []byte) unsafe.Pointer     { return unsafe.Pointer(&b[0]) }
func ptrOfU32(u *uint32) unsafe.Pointer { return unsafe.Pointer(u) }
