package heartbeat

import (
	"bg-agent/host"
	"bg-agent/model/request"
	"bg-agent/resource"
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"go.uber.org/zap"
)

func GetAgentStat() request.Records {

	agent := request.Records{}

	agent.KernelVersion = host.KernelVersion
	agent.Arch = host.Arch
	agent.Arch = host.Arch
	agent.Platform = host.Platform
	agent.PlatformFamily = host.PlatformFamily
	agent.PlatformVersion = host.PlatformVersion
	agent.TotalMem = strconv.FormatUint(resource.GetMemTotal(), 10)

	cpuPercent, rss, readSpeed, writeSpeed, fds, startAt, err := resource.GetProcResouce(os.Getpid())
	if err != nil {
		zap.S().Error(err)
	} else {
		agent.Cpu = strconv.FormatFloat(cpuPercent, 'f', 8, 64)
		agent.Rss = strconv.FormatUint(rss, 10)
		agent.ReadSpeed = strconv.FormatFloat(readSpeed, 'f', 8, 64)
		agent.WriteSpeed = strconv.FormatFloat(writeSpeed, 'f', 8, 64)
		agent.Pid = strconv.Itoa(os.Getpid())
		agent.Nfd = strconv.FormatInt(int64(fds), 10)
		agent.StartTime = strconv.FormatInt(startAt, 10)
	}
	// for transfer service

	agent.HostSerial, agent.HostId, agent.HostModel, agent.HostVendor = resource.GetHostInfo()

	agent.CpuName = resource.GetCPUName()
	agent.BootTime = strconv.FormatUint(resource.GetBootTime(), 10)
	if cpuPercents, err := cpu.Percent(0, false); err == nil && len(cpuPercents) != 0 {
		agent.CpuUsage = strconv.FormatFloat(cpuPercents[0]/100, 'f', 8, 64)
	}
	if mem, err := mem.VirtualMemory(); err == nil {
		agent.MemUsage = strconv.FormatFloat(mem.UsedPercent/100, 'f', 8, 64)
	}

	return agent
}

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	zap.S().Info("health daemon startup")
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			{
				host.RefreshHost()
			}
		}
	}
}
