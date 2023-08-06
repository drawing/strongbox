package securefs

import (
	"os"
	"testing"

	"github.com/shirou/gopsutil/v3/process"
)

func TestProcess(t *testing.T) {
	v, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatal("new process:", err)
	}

	ex, err := v.IsRunning()
	// fmt.Println(ex, ",", err)
	if err != nil {
		t.Fatal("IsRunning process:", err)
	}
	if !ex {
		t.Fatal("process not running")
	}
	// time.Sleep(2 * time.Second)
}
