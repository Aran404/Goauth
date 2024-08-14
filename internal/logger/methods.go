package log

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	types "github.com/Aran404/Goauth/internal/types"
	"github.com/charmbracelet/log"
	"golang.org/x/exp/constraints"
)

var (
	mutex = &sync.Mutex{}

	GetStackTrace = func() string {
		pc, fn, line, _ := runtime.Caller(1)
		stackTrace := fmt.Sprintf("%s[%s:%d]", runtime.FuncForPC(pc).Name(), fn, line)

		return stackTrace
	}

	GetExplicitTime = func() string {
		return time.Now().Format("01-02-2006 15:04:05")
	}
)

const (
	NInfo = iota
	NError
	NFatal
)

func AppendLine(filepath string, s string, m *sync.Mutex) error {
	m.Lock()
	defer m.Unlock()

	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(s + "\n")
	return err
}

func Error(stack string, format string, content ...any) {
	log.Error(fmt.Sprintf(format, content...))
	LogMessages(NError, fmt.Sprintf(format, content...), stack)
}

// When verbose is false, this function is a noop
func Info(format string, content ...any) {
	if !types.Cfg.Verbose {
		return
	}

	log.Info(fmt.Sprintf(format, content...))
}

func Fatal(stack string, format string, content ...any) {
	LogMessages(NFatal, fmt.Sprintf(format, content...), stack)
	log.Fatal(fmt.Sprintf(format, content...))
}

func LogMessages[T constraints.Integer, S comparable](level T, message S, stackTrace string) {
	var (
		logs  string
		err   error
		found bool
	)

	filePath, found := findEventsLogFile(".")
	if !found {
		log.Error("Could not find log file.")
		return
	}

	switch level {
	case NInfo:
		logs = fmt.Sprintf("%v [INFO] %v -> %v", GetExplicitTime(), stackTrace, message)
	case NError:
		logs = fmt.Sprintf("%v [ERROR] %v -> %v", GetExplicitTime(), stackTrace, message)
	case NFatal:
		logs = fmt.Sprintf("%v [FATAL] %v -> %v", GetExplicitTime(), stackTrace, message)
	}

	if err = AppendLine(filePath, logs, mutex); err != nil {
		log.Fatal("Could not log message: %v, Error: %v", message, err.Error())
	}
}

func findEventsLogFile(startDir string) (string, bool) {
	var filePath string
	found := false

	filepath.Walk(startDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Name() == "events.log" {
			filePath = path
			found = true
			return errors.New("found")
		}
		return nil
	})

	return filePath, found
}
