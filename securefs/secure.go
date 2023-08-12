package securefs

import (
	"context"
	"os"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/shirou/gopsutil/v3/process"

	"strongbox/configuration"
	cfg "strongbox/configuration"

	"github.com/hanwen/go-fuse/v2/fuse"
	log "github.com/sirupsen/logrus"
)

// /Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse
// var builtInProcess []string = []string{"mount_macfuse", "strongbox"}

const maxProcessCacheSize = 65535

type processItem struct {
	exec   string
	uptime time.Time
}

var processCache *lru.Cache[uint32, *processItem] = nil

/*
func execCmd(pid uint32) {

		timeout := 5
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+5)*time.Second)
		defer cancel()

		cmdarray := []string{"-c", fmt.Sprintf("ps -e -o pid,comm | grep %d", pid)}
		cmd := exec.CommandContext(ctx, "bash", cmdarray...)
		out, err := cmd.CombinedOutput()

		if err != nil {
			log.Error("out err", err)
			return
		}
		log.Printf("out:%s", string(out))
	}
*/
/*
func init() {
	var err error
	if processCache == nil {
		processCache, err = lru.New[uint32, *processItem](maxProcessCacheSize)
		if err != nil {
			log.Error("init lru.New error:", err)
			return
		}
	}
	ps, err := process.Processes()
	if err != nil {
		log.Error("init Processes get error:", err)
		return
	}
	for _, v := range ps {
		exeFile, err := v.Exe()
		if err != nil {
			continue
		}
		p := &processItem{exeFile, time.Now()}
		processCache.Add(uint32(v.Pid), p)
	}
}
*/

func CheckAllowProcess(action string, ctx context.Context) bool {
	var err error

	caller, ok := fuse.FromContext(ctx)
	if !ok {
		log.Error(action, " FromContext error")
		return false
	}
	// log.Debug("Enter PID:", caller.Pid)

	// 2023-08-04 23:46:53 [WARN] Getattr ----- new process start ----- 3102
	if os.Getpid() == int(caller.Pid) || 0 == caller.Pid {
		log.Debug("Leave 1 PID:", caller.Pid)
		return true
	}

	if processCache == nil {
		processCache, err = lru.New[uint32, *processItem](maxProcessCacheSize)
		if err != nil {
			log.Error(action, " lru.New error:", err)
			return false
		}
	}
	ps, ok := processCache.Get(caller.Pid)
	if !ok || ps.uptime.After(time.Now().Add(300*time.Second)) {
		// log.Warn(action, " ----- new process start ----- ", caller.Pid)
		nps, err := process.NewProcess(int32(caller.Pid))
		if err != nil {
			log.Error(action, " process.NewProcess error:", err)
			return false
		}
		exeFile, err := nps.Exe()
		if err != nil {
			log.Error(action, " ps.Exe error:", err)
			return false
		}

		// log.Warn(action, " ----- new process end ----- ", caller.Pid, ", ", exeFile)
		ps = &processItem{exeFile, time.Now()}
		processCache.Add(caller.Pid, ps)
	}

	for _, v := range configuration.Cfg.Permission.AllowProcess {
		if ps.exec == v {
			// log.Debug("Leave 2 PID:", caller.Pid)
			return true
		}
	}
	for _, v := range configuration.Cfg.Permission.DenyProcess {
		if ps.exec == v {
			log.Warn(action, " process(deny):", caller.Pid, " ", ps.exec, ", ", os.Getpid())
			return false
		}
	}

	if cfg.Cfg.Permission.DefaultAction == "pass" {
		log.Warn(action, " process(default pass):", caller.Pid, " ", ps.exec, ", ", os.Getpid())
		return true
	} else {
		// log.Debug("Leave 3 PID:", caller.Pid)
		log.Warn(action, " process(default deny):", caller.Pid, " ", ps.exec, ", ", os.Getpid())
		return false
	}
}
