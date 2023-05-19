package handle

import (
	"bg-agent/global"
	"bg-agent/internal/libs/Glog"
	"bg-agent/model/request"
	"bg-agent/model/response"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

/*
		AgentRegister
	 	Agent 启动时，向 Server 端注册的接口
		req: handle.AgentRegisterReq
*/

func ReportUpload(req request.UploadReq) {
	resp, body, errs := POST("/v2/report/upload", req).End()
	if len(errs) > 0 {
		for _, v := range errs {
			fmt.Println(v)
		}
		//fmt.Println("boom")
		return
	}
	if resp.StatusCode == 200 {
		var res response.ResBase
		err := json.Unmarshal([]byte(body), &res)
		if err != nil {
			fmt.Println(err)
			return
		}

		if res.Status == 201 {
			//fmt.Println("pang")
		} else {
			//fmt.Println(res.Msg)
		}

	}
}

func UploadResult(info *request.InputDataStruct) error {
	clien := http.Client{Timeout: time.Second * 5}
	url := global.WkgURL + "/v3/import?token=" + global.V3Token

	body, err := json.Marshal(info)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	resp, err := clien.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 200 {
		log.Println("data upload success.")
		Glog.InfoG("data upload success.")
	} else {
		log.Println("data upload failed. respstatus:", resp.Status)
		Glog.InfoG("data upload failed.")
	}
	return nil
}
