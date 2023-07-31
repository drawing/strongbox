package securefs

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/fuse/nodefs"
	log "github.com/sirupsen/logrus"

	ps "github.com/mitchellh/go-ps"
)

type secureNode struct {
	nodefs.Node
	fs *secureNodeFs
	id int

	path string

	mu   sync.Mutex
	link string
	info fuse.Attr
}

func (n *secureNode) newFile(f *os.File) nodefs.File {
	log.Debug("call newFile() ", f)
	return &secureNodeFile{
		File: nodefs.NewLoopbackFile(f),
		node: n,
	}
}

func (n *secureNode) Open(flags uint32, context *fuse.Context) (file nodefs.File, code fuse.Status) {
	log.Debug("call Open() ", flags, " ", context)

	process, err := ps.FindProcess(int(context.Pid))
	if err != nil {
		log.Debug("Open:", context.Pid, err)
	} else {
		log.Debug("Open:", context.Pid, process.Executable())
	}

	f, err := os.OpenFile(n.filename(), int(flags), 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	return n.newFile(f), fuse.OK
}

func (n *secureNode) GetAttr(fi *fuse.Attr, file nodefs.File, context *fuse.Context) (code fuse.Status) {
	log.Debug("call GetAttr() ", n.path, " ", fi, " ", file, " ", context)
	n.mu.Lock()
	defer n.mu.Unlock()

	*fi = n.info

	log.Debug("GetAttr ret", *fi)
	return fuse.OK
}

func (n *secureNode) Truncate(file nodefs.File, size uint64, context *fuse.Context) (code fuse.Status) {
	log.Debug("call Truncate() ", n.filename())
	if file != nil {
		code = file.Truncate(size)
	} else {
		err := os.Truncate(n.filename(), int64(size))
		code = fuse.ToStatus(err)
	}
	if code.Ok() {
		now := time.Now()

		n.mu.Lock()
		defer n.mu.Unlock()

		n.info.SetTimes(nil, nil, &now)
		// TODO - should update mtime too?
		n.info.Size = size
	}
	return code
}

func (n *secureNode) Utimens(file nodefs.File, atime *time.Time, mtime *time.Time, context *fuse.Context) (code fuse.Status) {
	log.Debug("call Utimens() ", n.filename())
	c := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()

	n.info.SetTimes(atime, mtime, &c)
	return fuse.OK
}

func (n *secureNode) Chmod(file nodefs.File, perms uint32, context *fuse.Context) (code fuse.Status) {
	log.Debug("call Chmod() ", n.filename())
	n.info.Mode = (n.info.Mode &^ 07777) | perms
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	n.info.SetTimes(nil, nil, &now)
	return fuse.OK
}

func (n *secureNode) Chown(file nodefs.File, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	log.Debug("call Chown() ", n.filename())
	n.info.Uid = uid
	n.info.Gid = gid
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	n.info.SetTimes(nil, nil, &now)
	return fuse.OK
}

func (n *secureNode) filename() string {
	return fmt.Sprintf("%s/%s", n.fs.secretPath, n.path)
}

func (n *secureNode) Deletable() bool {
	log.Debug("call Deletable() ", n.filename())
	return false
}

func (n *secureNode) Readlink(c *fuse.Context) ([]byte, fuse.Status) {
	log.Debug("call Readlink() ", n.filename())
	n.mu.Lock()
	defer n.mu.Unlock()
	return []byte(n.link), fuse.OK
}

func (n *secureNode) StatFs() *fuse.StatfsOut {
	log.Debug("call StatFs() ", n.filename())
	return &fuse.StatfsOut{}
}

func (n *secureNode) Mkdir(name string, mode uint32, context *fuse.Context) (newNode *nodefs.Inode, code fuse.Status) {
	log.Debug("call Mkdir() ", name, " ", mode, " ", context)

	ch := n.fs.newNode(n.path + "/" + name)
	ch.info.Mode = mode | fuse.S_IFDIR

	err := os.Mkdir(ch.filename(), os.FileMode(mode))
	if err != nil {
		log.Error("Mkdir error ", ch.filename(), ",", err)
		return nil, fuse.ToStatus(err)
	}
	// TODO
	n.Inode().NewChild(name, true, ch)
	return ch.Inode(), fuse.OK
}

func (n *secureNode) OpenDir(context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	log.Debug("call OpenDir() ", context, " ", n.filename())

	entries, err := os.ReadDir(n.filename())
	if err != nil {
		log.Error("ReadDir error ", n.filename(), ",", err)
		return nil, fuse.ToStatus(err)
	}

	infos := make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			log.Error("entry info error ", err)
			return nil, fuse.ToStatus(err)
		}

		infos = append(infos, fuse.DirEntry{Name: info.Name(), Mode: uint32(info.Mode())})

		/* add cliend node */
		ch := n.fs.newNode(n.path + "/" + info.Name())
		ch.info.Mtime = uint64(info.ModTime().Unix())
		ch.info.Mode = uint32(info.Mode())
		n.Inode().NewChild(info.Name(), info.IsDir(), ch)
	}
	log.Debug("call OpenDir ret ", infos)
	return infos, fuse.OK
}

func (n *secureNode) Unlink(name string, context *fuse.Context) (code fuse.Status) {
	log.Debug("call Unlink() ", n.filename())
	ch := n.Inode().RmChild(name)
	if ch == nil {
		return fuse.ENOENT
	}
	return fuse.OK
}

func (n *secureNode) Rmdir(name string, context *fuse.Context) (code fuse.Status) {
	log.Debug("call Rmdir() ", n.filename())
	return n.Unlink(name, context)
}

func (n *secureNode) Symlink(name string, content string, context *fuse.Context) (newNode *nodefs.Inode, code fuse.Status) {
	log.Debug("call Symlink() ", n.filename())
	ch := n.fs.newNode(name)
	ch.info.Mode = fuse.S_IFLNK | 0777
	ch.link = content
	n.Inode().NewChild(name, false, ch)
	return ch.Inode(), fuse.OK
}

func (n *secureNode) Rename(oldName string, newParent nodefs.Node, newName string, context *fuse.Context) (code fuse.Status) {
	log.Debug("call Rename() ", n.filename())
	ch := n.Inode().RmChild(oldName)
	newParent.Inode().RmChild(newName)
	newParent.Inode().AddChild(newName, ch)
	return fuse.OK
}

func (n *secureNode) Link(name string, existing nodefs.Node, context *fuse.Context) (*nodefs.Inode, fuse.Status) {
	log.Debug("call Link() ", n.filename())
	n.Inode().AddChild(name, existing.Inode())
	return existing.Inode(), fuse.OK
}

func (n *secureNode) Create(name string, flags uint32, mode uint32, context *fuse.Context) (file nodefs.File, node *nodefs.Inode, code fuse.Status) {
	log.Debug("call Create() ", name, " ", mode, " ", mode, " ", context)

	ch := n.fs.newNode(n.path + "/" + name)
	ch.info.Mode = mode | fuse.S_IFREG

	f, err := os.Create(ch.filename())
	if err != nil {
		return nil, nil, fuse.ToStatus(err)
	}
	n.Inode().NewChild(name, false, ch)
	return ch.newFile(f), ch.Inode(), fuse.OK
}
