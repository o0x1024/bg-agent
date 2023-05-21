package wkgApi

import (
	"bg-agent/global"
	"bg-agent/model/request"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

var (
	client *http.Client
	req    *http.Request
)

func UpdateDomainResToServer(result request.DomainScanRes) error {

	client = &http.Client{Timeout: time.Duration(5) * time.Second}

	data, err := json.Marshal(result)
	if err != nil {
		zap.S().Errorln(err)
		return err
	}

	req, err := http.NewRequest("POST", global.WkgURL+"/v3/task/uploadDomains?token=41f330686cbf9e21d9f092c68d032b03e24c7284", bytes.NewReader(data))

	if err != nil {
		zap.S().Errorln(err)
		return err
	}
	// req.Header.Add("token", "41f330686cbf9e21d9f092c68d032b03e24c7284")

	resp, err := client.Do(req)
	if err != nil {
		zap.S().Errorln(err)
		return err
	}

	if resp.StatusCode == 200 {
		zap.S().Infoln("upload success.")
		return err
	}

	body, _ := io.ReadAll(resp.Body)
	zap.S().Infoln(string(body))

	return nil

}
