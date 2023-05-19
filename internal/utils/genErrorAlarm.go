package utils

import (
	types2 "bg-agent/model/types"
	"runtime"
)

func GenReportInfo(err error) types2.Alarm {
	var alarm types2.Alarm
	alarm.Type = 1
	var buf [2 << 10]byte
	stack := string(buf[:runtime.Stack(buf[:], true)])
	alarm.Stack = stack
	alarm.Detail = err.Error()
	alarm.Timetamp = GetCurTime()

	return alarm
}
