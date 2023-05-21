package main

import (
	"bg-agent/agent"
	"bg-agent/heartbeat"
	"bg-agent/host"
	"bg-agent/internal/taskCore"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"bg-agent/transport"

	"github.com/kataras/golog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	sigs := make(chan os.Signal, 1)
	t := time.Now()

	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "log/" + agent.Product + ".log",
		MaxSize:    1, // megabytes
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})

	var core zapcore.Core

	core = zapcore.NewTee(
		zapcore.NewSamplerWithOptions(
			zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel), time.Second, 4, 1),
	)

	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	zap.S().Info("++++++++++++++++++++++++++++++startup++++++++++++++++++++++++++++++")
	zap.S().Info("product:", agent.Product)
	zap.S().Info("version:", agent.Version)
	zap.S().Info("id:", agent.ID)
	zap.S().Info("hostname:", host.Name.Load())
	zap.S().Infof("intranet_ipv4:%v", host.PrivateIPv4.Load())
	zap.S().Infof("intranet_ipv6:%v", host.PrivateIPv6.Load())
	zap.S().Infof("extranet_ipv4:%v", host.PublicIPv4.Load())
	zap.S().Infof("extranet_ipv6:%v", host.PublicIPv6.Load())
	zap.S().Info("platform:", host.Platform)
	zap.S().Info("platform_family:", host.PlatformFamily)
	zap.S().Info("platform_version:", host.PlatformVersion)
	zap.S().Info("kernel_version:", host.KernelVersion)
	zap.S().Info("arch:", host.Arch)
	wg := &sync.WaitGroup{}
	zap.S().Info("++++++++++++++++++++++++++++++running++++++++++++++++++++++++++++++")

	fmt.Println("[+] agent starting.")

	go heartbeat.Startup(agent.Context, wg)
	go transport.StartTransfer(agent.Context, wg)

	go taskCore.Run(agent.Context, wg)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigs:
		fmt.Print("\n")
		golog.Info("receive signal:", sig)
		golog.Info("task exit.")
		golog.Info("Wait for the task to end.")
		time.Sleep(3)
	}

	log.Println("[*] run time:", time.Since(t))

}
