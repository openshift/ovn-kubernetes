package rpc2

import "log"

// DebugLog controls the printing of internal and I/O errors.
var DebugLog = true

func debugln(v ...interface{}) {
	if DebugLog {
		log.Println(v...)
	}
}
