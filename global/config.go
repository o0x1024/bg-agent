package global

import "bg-agent/model/request"

var (
	AttackQueue = make(chan request.UploadReq, 50)
)
