package Glog

import (
	"bg-agent/internal/utils"
	"io"
	"log"
	"os"
)

const (
	flag       = log.Ldate | log.Ltime | log.Lshortfile
	preDebug   = "[DEBUG]"
	preInfo    = "[INFO]"
	preWarning = "[WARNING]"
	preError   = "[ERROR]"
)

var (
	logFile       io.Writer
	debugLogger   *log.Logger
	infoLogger    *log.Logger
	warningLogger *log.Logger
	errorLogger   *log.Logger
	infolog       = "./log/info.log"
	errlog        = "./log/err.log"
)

func InitLog() {
	var err error
	ex, err := utils.PathExists("log")
	if err != nil {
		log.Fatalln(err)
	}
	if !ex {
		err = os.MkdirAll("log", os.ModePerm)
		if err != nil {
			log.Fatalln(err)
		}
	}

	infologfile, err := os.OpenFile(infolog, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
	errlogfile, err := os.OpenFile(errlog, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
	debugLogger = log.New(logFile, preDebug, flag)
	infoLogger = log.New(infologfile, preInfo, flag)

	warningLogger = log.New(logFile, preWarning, flag)

	errorLogger = log.New(errlogfile, preError, flag)
}

func DebugG(format string, v ...interface{}) {
	debugLogger.Printf(format, v...)
}

func InfoG(format string, v ...interface{}) {
	infoLogger.Printf(format, v...)
}

func WarningG(format string, v ...interface{}) {
	warningLogger.Printf(format, v...)
}

func ErrorG(format string, v ...interface{}) {
	errorLogger.Printf(format, v...)
}

func SetOutputPath(path string) {
	var err error
	logFile, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalf("create log file err %+v", err)
	}
	debugLogger.SetOutput(logFile)
	infoLogger.SetOutput(logFile)
	warningLogger.SetOutput(logFile)
	errorLogger.SetOutput(logFile)
}
