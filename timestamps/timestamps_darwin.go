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

	stat := fi.Sys().(*syscall.Stat_t)
	wts.Modified = cm.FormatTimestamp(time.Unix(int64(stat.Mtimespec.Sec), int64(stat.Mtimespec.Nsec)).UTC())
	wts.Accessed = cm.FormatTimestamp(time.Unix(int64(stat.Atimespec.Sec), int64(stat.Atimespec.Nsec)).UTC())
	wts.Created = cm.FormatTimestamp(time.Unix(int64(stat.Ctimespec.Sec), int64(stat.Ctimespec.Nsec)).UTC())
	wts.Birth = cm.FormatTimestamp(time.Unix(int64(stat.Birthtimespec.Sec), int64(stat.Birthtimespec.Nsec)).UTC())
	return
}
