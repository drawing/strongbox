package securefs

import (
	"fmt"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/fuse/nodefs"
)

type secureNodeFile struct {
	nodefs.File
	node *secureNode
}

// The String method is for debug printing.
func (n *secureNodeFile) String() string {
	return fmt.Sprintf("SecureNodeFile(%s)", n.File.String())
}

func (n *secureNodeFile) InnerFile() nodefs.File {
	return n.File
}

func (n *secureNodeFile) Read(dest []byte, off int64) (fuse.ReadResult, fuse.Status) {
	// TODO encode
	return n.File.Read(dest, off)
}
func (n *secureNodeFile) Write(data []byte, off int64) (written uint32, code fuse.Status) {
	// TODO decode
	return n.File.Write(data, off)
}
