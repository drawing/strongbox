package securefs

import (
	"context"
	"os"
	"sync"
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
var processCacheMu sync.Mutex

var forbidCache *lru.Cache[string, time.Time] = nil

func init() {
	forbidCache, _ = lru.New[string, time.Time](maxProcessCacheSize)
}

func GetForbidProcess() []string {
	if forbidCache == nil {
		return []string{}
	} else {
		return forbidCache.Keys()
	}
}

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

	if os.Getpid() == int(caller.Pid) || 0 == caller.Pid {
		log.Debug("Leave 1 PID:", caller.Pid)
		return true
	}

	processCacheMu.Lock()
	if processCache == nil {
		processCache, err = lru.New[uint32, *processItem](maxProcessCacheSize)
		if err != nil {
			processCacheMu.Unlock()
			log.Error(action, " lru.New error:", err)
			return false
		}
	}
	processCacheMu.Unlock()
	
	ps, ok := processCache.Get(caller.Pid)
	if !ok || time.Now().After(ps.uptime.Add(300*time.Second)) {
		exeFile := getProcessExeWithTimeout(caller.Pid)
		if exeFile == "" {
			log.Error(action, " get process exe failed, PID:", caller.Pid)
			if ok {
				log.Warn(action, " using cached process info, PID:", caller.Pid)
			} else {
				return false
			}
		} else {
			ps = &processItem{exeFile, time.Now()}
			processCache.Add(caller.Pid, ps)
		}
	}

	for _, v := range configuration.Cfg.Permission.AllowProcess {
		if ps.exec == v {
			return true
		}
	}
	for _, v := range configuration.Cfg.Permission.DenyProcess {
		if ps.exec == v {
			log.Warn(action, " process(deny):", caller.Pid, " ", ps.exec, ", ", os.Getpid())
			forbidCache.Add(ps.exec, time.Now())
			return false
		}
	}

	if cfg.Cfg.Permission.DefaultAction == "pass" {
		log.Warn(action, " process(default pass):", caller.Pid, " ", ps.exec, ", ", os.Getpid())
		return true
	} else {
		log.Warn(action, " process(default deny):", caller.Pid, " ", ps.exec, ", ", os.Getpid())
		forbidCache.Add(ps.exec, time.Now())
		return false
	}
}

func getProcessExeWithTimeout(pid uint32) string {
	resultChan := make(chan string, 1)
	
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("getProcessExeWithTimeout panic:", r)
				resultChan <- ""
			}
		}()
		
		nps, err := process.NewProcess(int32(pid))
		if err != nil {
			log.Error("process.NewProcess error:", err)
			resultChan <- ""
			return
		}
		
		exeFile, err := nps.Exe()
		if err != nil {
			log.Error("ps.Exe error:", err)
			resultChan <- ""
			return
		}
		
		resultChan <- exeFile
	}()
	
	select {
	case exeFile := <-resultChan:
		return exeFile
	case <-time.After(100 * time.Millisecond):
		log.Warn("getProcessExeWithTimeout timeout, PID:", pid)
		return ""
	}
}
