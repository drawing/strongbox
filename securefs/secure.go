package securefs

import (
	"context"
	"os"

	ps "github.com/mitchellh/go-ps"
	log "github.com/sirupsen/logrus"

	"strongbox/configuration"

	"github.com/hanwen/go-fuse/v2/fuse"
)

var builtInProcess []string = []string{"mount_macfuse", "strongbox"}

func CheckAllowProcess(action string, ctx context.Context) bool {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		log.Error(action, " FromContext error")
		return false
	}
	if os.Getpid() == int(caller.Pid) || 0 == caller.Pid {
		return true
	}

	process, err := ps.FindProcess(int(caller.Pid))
	if err != nil {
		log.Debug(action, " process error:", caller.Pid, " ", err)
		return false
	} else {
		log.Debug(action, " process:", caller.Pid, " ", process.Executable())
	}

	for _, v := range builtInProcess {
		if process.Executable() == v {
			return true
		}
	}
	for _, v := range configuration.Cfg.AllowProcess {
		if process.Executable() == v {
			return true
		}
	}

	log.Warn(action, " process forbid:", caller.Pid, " ", process.Executable())
	return false
}
