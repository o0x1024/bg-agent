package request

import (
	"bg-agent/global"
	"log"
	"net/http"
	"strings"
	"time"
)

type RespType struct {
	Code int      `json:"code"`
	Msg  string   `json:"msg"`
	Data []string `json:"data"`
}

func BugReport(detail string) {
	client := http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("POST", global.WkgURL+"/v2/bugReport", strings.NewReader(detail))
	_, err := client.Do(req)
	if err != nil {
		log.Println("[!] buf upload failed. error:[", err, "]")
		return
	}

}
