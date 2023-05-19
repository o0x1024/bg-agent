package transport

import (
	"bg-agent/agent"
	"bg-agent/global"
	"bg-agent/heartbeat"
	"bg-agent/host"
	"bg-agent/model/request"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var (
	txCnt      = uint64(0)
	rxCnt      = uint64(0)
	updateTime = time.Now()
)

func GetState(now time.Time) (txTPS, rxTPS float64) {
	instant := now.Sub(updateTime).Seconds()
	if instant != 0 {
		txTPS = float64(atomic.SwapUint64(&txCnt, 0)) / float64(instant)
		rxTPS = float64(atomic.SwapUint64(&rxCnt, 0)) / float64(instant)
	}
	updateTime = now
	return
}

func StartTransfer(ctx context.Context, wg *sync.WaitGroup) {
	go handleSend()
}

func hbsend(pkdata request.PackagedData) error {

	client := http.Client{Timeout: 5 * time.Second}

	data, err := json.Marshal(&pkdata)
	if err != nil {
		zap.S().Error(err)
		return err
	}

	req, _ := http.NewRequest("POST", global.HeartBeatAPI, bytes.NewReader(data))

	resp, err := client.Do(req)
	if err != nil {
		zap.S().Error(err)
		return err
	}

	if resp.StatusCode != 200 {
		zap.S().Error("heartbeat failed.")
	}
	return nil
}

func handleSend() {
	defer zap.S().Info("send handler will exit")
	// 停止发送数据
	zap.S().Info("send handler running")
	ticker := time.NewTicker(time.Second * 180)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			{
				recs := heartbeat.GetAgentStat()
				pk := request.PackagedData{
					Records:      recs,
					AgentId:      agent.ID,
					IntranetIpv4: host.PrivateIPv4.Load().([]string),
					IntranetIpv6: host.PrivateIPv6.Load().([]string),
					ExtranetIpv4: host.PublicIPv4.Load().([]string),
					ExtranetIpv6: host.PublicIPv6.Load().([]string),
					Hostname:     host.Name.Load().(string),
					Version:      agent.Version,
					Product:      agent.Product,
				}
				zap.S().Info(pk)
				err := hbsend(pk)
				if err != nil {
					zap.S().Error(err)
				}
			}
		}
	}
}
