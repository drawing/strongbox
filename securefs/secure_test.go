package securefs

import (
	"context"
	"os"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	cfg "strongbox/configuration"
)

func init() {
	cfg.Cfg.Backup.Memory = true
	err := GetDBInstance().InitDB()
	if err != nil {
		panic(err)
	}
}

func TestCheckAllowProcess_SelfProcess(t *testing.T) {
	ctx := context.TODO()
	caller := fuse.Caller{}
	caller.Pid = uint32(os.Getpid())
	ctx = fuse.NewContext(ctx, &caller)

	result := CheckAllowProcess("Test", ctx)
	if !result {
		t.Fatal("Self process should be allowed")
	}
}

func TestCheckAllowProcess_ZeroPid(t *testing.T) {
	ctx := context.TODO()
	caller := fuse.Caller{}
	caller.Pid = 0
	ctx = fuse.NewContext(ctx, &caller)

	result := CheckAllowProcess("Test", ctx)
	if !result {
		t.Fatal("Zero PID should be allowed")
	}
}

func TestCheckAllowProcess_AllowList(t *testing.T) {
	ctx := context.TODO()
	caller := fuse.Caller{}
	caller.Pid = uint32(os.Getpid())
	ctx = fuse.NewContext(ctx, &caller)

	cfg.Cfg.Permission.AllowProcess = []string{"/proc/self/exe"}
	
	result := CheckAllowProcess("Test", ctx)
	if !result {
		t.Fatal("Process in allow list should be allowed")
	}
}

func TestCheckAllowProcess_DenyList(t *testing.T) {
	ctx := context.TODO()
	caller := fuse.Caller{}
	caller.Pid = uint32(os.Getpid())
	ctx = fuse.NewContext(ctx, &caller)

	cfg.Cfg.Permission.AllowProcess = []string{}
	cfg.Cfg.Permission.DenyProcess = []string{"/proc/self/exe"}
	
	result := CheckAllowProcess("Test", ctx)
	if result {
		t.Fatal("Process in deny list should be denied")
	}
}

func TestCheckAllowProcess_DefaultPass(t *testing.T) {
	ctx := context.TODO()
	caller := fuse.Caller{}
	caller.Pid = uint32(os.Getpid())
	ctx = fuse.NewContext(ctx, &caller)

	cfg.Cfg.Permission.AllowProcess = []string{}
	cfg.Cfg.Permission.DenyProcess = []string{}
	cfg.Cfg.Permission.DefaultAction = "pass"
	
	result := CheckAllowProcess("Test", ctx)
	if !result {
		t.Fatal("Default action pass should allow process")
	}
}

func TestCheckAllowProcess_DefaultDeny(t *testing.T) {
	ctx := context.TODO()
	caller := fuse.Caller{}
	caller.Pid = uint32(os.Getpid())
	ctx = fuse.NewContext(ctx, &caller)

	cfg.Cfg.Permission.AllowProcess = []string{}
	cfg.Cfg.Permission.DenyProcess = []string{}
	cfg.Cfg.Permission.DefaultAction = "deny"
	
	result := CheckAllowProcess("Test", ctx)
	if result {
		t.Fatal("Default action deny should deny process")
	}
}
