package securefs

import (
	"fmt"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/fuse/nodefs"

	log "github.com/sirupsen/logrus"
)

// NewMemNodeFSRoot creates an in-memory node-based filesystem. Files
// are written into a backing store under the given prefix.
func NewSecureNodeFSRoot(secretPath string) nodefs.Node {
	fs := &secureNodeFs{
		secretPath: secretPath,
	}
	fs.root = fs.newNode("/")
	return fs.root
}

type secureNodeFs struct {
	secretPath string
	root       *secureNode

	mutex    sync.Mutex
	nextFree int
}

func (fs *secureNodeFs) String() string {
	log.Debug("call secureNodeFs String()")
	return fmt.Sprintf("SecureNodeFs(%s)", fs.secretPath)
}

func (fs *secureNodeFs) OnMount(c *nodefs.FileSystemConnector) {
	log.Debug("call OnMount() ", c)
}

func (fs *secureNodeFs) OnUnmount() {
	log.Debug("call OnUnmount()")
}

func (fs *secureNodeFs) newNode(name string) *secureNode {
	log.Debug("call newNode() ", name)

	n := &secureNode{
		Node: nodefs.NewDefaultNode(),
		fs:   fs,
		path: name,
	}
	now := time.Now()
	n.info.SetTimes(&now, &now, &now)
	n.info.Mode = fuse.S_IFDIR | 0777
	return n
}

func (fs *secureNodeFs) Filename(n *nodefs.Inode) string {
	mn := n.Node().(*secureNode)
	return mn.filename()
}
