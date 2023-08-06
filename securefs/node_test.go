package securefs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	cfg "strongbox/configuration"
)

func init() {
	cfg.Cfg.BackupInMemory = true
	err := GetDBInstance().InitDB()
	if err != nil {
		fmt.Println("InitDB:", err)
	}
}

func TestMkdir(t *testing.T) {
	n := &BoxInode{}

	ctx := context.TODO()
	caller := fuse.Caller{}
	caller.Pid = uint32(os.Getpid())
	ctx = fuse.NewContext(ctx, &caller)

	attr := fuse.EntryOut{}

	inode, err := n.Mkdir(ctx, "dir1", 0, &attr)
	if err != fs.OK || inode == nil {
		t.Fatal("Mkdir error:", err)
	}
}

func TestJsonUnmarshal(t *testing.T) {

	root := &BoxInode{}
	root.Name = "Test Root"

	root.AddChildNode("1.txt")
	c := root.AddChildNode("dir1")
	c.AddChildNode("dir2")

	data, err := json.Marshal(root)

	root_new := &BoxInode{}
	err = json.Unmarshal(data, root_new)
	if err != nil {
		t.Fatal("Decode:", err)
	}

	if root.Name != root_new.Name {
		t.Fatal("root.Name not equal")
	}
	if root.parent != root_new.parent {
		t.Fatal("root.Parent not equal")
	}
	if len(root.ChildrenNode) != len(root_new.ChildrenNode) {
		t.Fatal("root_new.Children len not equal")
	}
}
