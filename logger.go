package proxy

import (
	"fmt"
	"log/slog"
)

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// logger 默认日志记录器
type logger struct {
	logger *slog.Logger
}

// 全局日志实例
var defaultLogger Logger = &logger{logger: slog.Default()}

// GetLogger 获取全局日志器
func GetLogger() Logger {
	return defaultLogger
}

func (l *logger) Debugf(format string, args ...any) {
	l.logger.Debug(sprintf(format, args...))
}

func (l *logger) Infof(format string, args ...any) {
	l.logger.Info(sprintf(format, args...))
}

func (l *logger) Warnf(format string, args ...any) {
	l.logger.Warn(sprintf(format, args...))
}

func (l *logger) Errorf(format string, args ...any) {
	l.logger.Error(sprintf(format, args...))
}

// sprintf 格式化字符串
func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
