package log

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

var Logger *logrus.Logger
var LogFile *os.File

type FileHook struct {
	Writer    io.Writer
	LogLevels []logrus.Level
}

func (hook *FileHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	_, err = hook.Writer.Write([]byte(line))
	//if err != nil {
	//	fmt.Printf("Error writing log: %v\n", err)
	//} else {
	//	fmt.Printf("Successfully wrote log entry: %s\n", line)
	//}
	return err
}

func Info(args ...interface{}) {
	Logger.Info(args)
}

func Infof(format string, args ...interface{}) {
	Logger.Infof(format, args)
}

func Error(args ...interface{}) {
	Logger.Error(args)
}

func Errorf(format string, args ...interface{}) {
	Logger.Errorf(format, args)
}

func (hook *FileHook) Levels() []logrus.Level {
	return hook.LogLevels
}

func InitLogger(path string) {
	Logger = logrus.New()
	Logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	Logger.SetLevel(logrus.InfoLevel)
	Logger.SetReportCaller(true) // Enable reporting caller info

	infoFile, err := os.OpenFile(path+"/info.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		Logger.Fatal(err)
	}

	errorFile, err := os.OpenFile(path+"/error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err != nil {
		Logger.Fatal(err)
	}

	Logger.SetOutput(os.Stdout)

	Logger.AddHook(&FileHook{
		Writer: infoFile,
		LogLevels: []logrus.Level{
			logrus.InfoLevel,
			logrus.WarnLevel,
		},
	})

	Logger.AddHook(&FileHook{
		Writer: errorFile,
		LogLevels: []logrus.Level{
			logrus.ErrorLevel,
			logrus.FatalLevel,
			logrus.PanicLevel,
		},
	})
	Logger.Info("Logger initialized")
}
