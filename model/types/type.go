package types

type VulnInfo struct {
	Level string
	Detail string
	Timetamp string
}

type ProgramErrInfo struct {
	msg string
}

type Alarm struct {
	Type int
	Stack string
	VulnInfo
	ProgramErrInfo
}