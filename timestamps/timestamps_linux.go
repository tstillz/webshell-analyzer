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
	wts.Modified = cm.FormatTimestamp(time.Unix(int64(stat.Mtim.Sec), int64(stat.Mtim.Nsec)).UTC())
	wts.Accessed = cm.FormatTimestamp(time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec)).UTC())
	wts.Created = cm.FormatTimestamp(time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)).UTC())
	return
}
