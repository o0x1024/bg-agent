package taskCore

import (
	"bg-agent/global"
	"bg-agent/internal/assetCollect/subfinder"
	"bg-agent/internal/libs/enc"
	"bg-agent/model/response"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

func Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	timer := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			zap.S().Info("context has been canceled, will shutdown all plugins")
		case <-timer.C:
			task, err := getTask()
			if err == nil && task != nil {
				execTask(task)

			}
		}
	}
}

// taskid
// 1000 信息搜集-域名-全部方式
// 1001 信息搜集-域名-接口扫描
// 1002 信息搜集-域名-暴力破解
// 1003 信息搜集-域名-暴力破解
func execTask(task *response.Task) {
	zap.S().Infoln("Start task task Id:", task.TaskId)
	switch task.TaskNo {
	case 1000:
	case 1001:
		subfinder.ColletDomainByInterface(task)
	case 1002:
		// domain.ColletDomainByKSubdomain(task)
	case 1003:

	case 1004:

	}
}

func getTask() (task *response.Task, err error) {
	GetTaskUrl := global.WkgURL + "/v3/task/getTask?token=" + global.V3Token
	client := http.Client{}

	req, _ := http.NewRequest("GET", GetTaskUrl, nil)
	resp, err := client.Do(req)
	if err != nil {
		zap.S().Error(err)
		return
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		zap.S().Error(err)
		return
	}

	zap.S().Info(string(buf))

	wr := response.WkgRes{}
	err = json.Unmarshal(buf, &wr)
	if err != nil {
		zap.S().Error(err)
		return
	}
	if wr.Code == 400 {
		return
	}

	zap.S().Info(string(wr.Data))
	//aes解密
	decTaskData, err := enc.DecryptByAes(string(wr.Data))
	if err != nil {
		zap.S().Error(err)
		return
	}

	zap.S().Info(string(decTaskData))

	_task := response.Task{}
	err = json.Unmarshal(decTaskData, &_task)
	if err != nil {
		zap.S().Error(err)
		return nil, err
	}

	return &_task, nil
}
