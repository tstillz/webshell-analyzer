package timestamps

import (
	cm "../common"
	"os"
	"syscall"
	"time"
)

func StatTimes(filePath string) (wts cm.FileTimes, err error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return
	}

	// https://golang.org/src/os/types_windows.go Line:215
	tsInfo := fi.Sys().(*syscall.Win32FileAttributeData)
	wts.Created = cm.FormatTimestamp(time.Unix(0, tsInfo.CreationTime.Nanoseconds()))
	wts.Accessed = cm.FormatTimestamp(time.Unix(0, tsInfo.LastAccessTime.Nanoseconds()))
	wts.Modified = cm.FormatTimestamp(time.Unix(0, tsInfo.LastWriteTime.Nanoseconds()))
	return
}
