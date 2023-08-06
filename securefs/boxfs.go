package securefs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"

	cfg "strongbox/configuration"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	log "github.com/sirupsen/logrus"
)

func NewRootBoxInode() (*BoxInode, error) {
	n := &BoxInode{}

	err := LoadRootDirFromDB(n)
	if err == os.ErrNotExist {
		var out fuse.EntryOut

		out.Mode = 0755 | syscall.S_IFDIR

		fd, err := syscall.Open(cfg.Cfg.MountPoint, os.O_RDONLY, 0)
		if err == nil {
			st := syscall.Stat_t{}
			if err := syscall.Fstat(fd, &st); err == nil {
				out.FromStat(&st)
			}
			syscall.Close(fd)
		}

		n.Name = ""
		n.root = n
		n.Attr.SetFromFuse(&out.Attr)
		return n, nil
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

type BoxAttr struct {
	Ino   uint64    `json:"ino"`
	Size  uint64    `json:"size"`
	Atime time.Time `json:"atime"`
	Mtime time.Time `json:"mtime"`
	Ctime time.Time `json:"ctime"`
	Mode  uint32    `json:"mode"`
	Uid   uint32    `json:"uid"`
	Gid   uint32    `json:"gid"`
}

func (a *BoxAttr) GetToFuse(out *fuse.Attr) {
	out.Ino = a.Ino
	out.Size = a.Size
	out.Atime = uint64(a.Atime.Unix())
	out.Mtime = uint64(a.Mtime.Unix())
	out.Ctime = uint64(a.Ctime.Unix())
	out.Atimensec = uint32(a.Atime.Nanosecond())
	out.Mtimensec = uint32(a.Mtime.Nanosecond())
	out.Ctimensec = uint32(a.Ctime.Nanosecond())
	out.Mode = a.Mode
	out.Uid = a.Uid
	out.Gid = a.Gid
}
func (a *BoxAttr) SetFromFuse(out *fuse.Attr) {
	out.Ino = a.Ino
	a.Size = out.Size
	a.Atime = time.Unix(int64(out.Atime), int64(out.Atimensec))
	a.Mtime = time.Unix(int64(out.Mtime), int64(out.Mtimensec))
	a.Ctime = time.Unix(int64(out.Ctime), int64(out.Ctimensec))
	a.Mode = out.Mode
	a.Uid = out.Uid
	a.Gid = out.Gid
}
func (a *BoxAttr) SetFromAttrIn(in *fuse.SetAttrIn) {
	if m, ok := in.GetMode(); ok {
		a.Mode = m
	}

	uid, uok := in.GetUID()
	gid, gok := in.GetGID()
	if uok || gok {
		a.Uid = uid
		a.Gid = gid
	}

	mtime, mok := in.GetMTime()
	atime, aok := in.GetATime()
	if mok || aok {
		a.Atime = atime
		a.Mtime = mtime
	}

	if sz, ok := in.GetSize(); ok {
		a.Size = sz
	}
}

type BoxInode struct {
	fs.Inode

	Name         string               `json:"name"`
	Attr         BoxAttr              `json:"attr"`
	ChildrenNode map[string]*BoxInode `json:"children"`

	parent *BoxInode
	root   *BoxInode
}

func (n *BoxInode) AddChildNode(name string) *BoxInode {
	if n.ChildrenNode == nil {
		n.ChildrenNode = make(map[string]*BoxInode)
	}
	c, ok := n.ChildrenNode[name]
	if !ok {
		c = &BoxInode{}
		c.Name = name
		c.parent = n
		c.root = n.root
		n.ChildrenNode[name] = c
	}

	return c
}

func (n *BoxInode) AddExistChildNode(name string, node *BoxInode) {
	if n.ChildrenNode == nil {
		n.ChildrenNode = make(map[string]*BoxInode)
	}
	n.ChildrenNode[name] = node
	node.parent = n
}

func (n *BoxInode) DelChildNode(name string) {
	if n.ChildrenNode == nil {
		return
	}
	delete(n.ChildrenNode, name)
}

func (n *BoxInode) GetChildNode(name string) (*BoxInode, error) {
	if n.ChildrenNode == nil {
		return nil, os.ErrNotExist
	}
	c, ok := n.ChildrenNode[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return c, nil
}

func (n *BoxInode) UpdateToDB() error {
	data, err := json.Marshal(n.root)

	// log.Println("TEST_UP:", string(data))
	err = GetDBInstance().Set([]byte("-"), data)
	if err != nil {
		log.Error("root dir set error:", err)
		return err
	}

	return nil
}

func setParentNode(b *BoxInode, parent *BoxInode, root *BoxInode) {
	b.root = root
	b.parent = parent

	if b.ChildrenNode != nil {
		for _, v := range b.ChildrenNode {
			setParentNode(v, b, root)
		}
	}
}

func LoadRootDirFromDB(b *BoxInode) error {
	data, err := GetDBInstance().Get([]byte("-"))
	if err != nil {
		log.Error("root dir set error:", err)
		return err
	}
	if len(data) == 0 {
		return os.ErrNotExist
	}

	// log.Println("LOAD_DB:", string(data))
	err = json.Unmarshal(data, b)
	if err != nil {
		return err
	}

	// log.Println("LOAD_DB: children=", len(b.ChildrenNode))

	b.root = b
	if b.ChildrenNode != nil {
		for _, v := range b.ChildrenNode {
			// log.Println("LOAD_DB_ITEM:", v)
			setParentNode(v, b, b)
		}
	}

	log.Println("Load: root dir load success")

	return nil
}

func (n *BoxInode) Path() string {
	var c *BoxInode = n
	path := c.Name
	if path == "" {
		path = "/"
	}
	c = c.parent
	for c != nil {
		path = c.Name + "/" + path
		c = c.parent
	}
	return path
}

// ------------------------- inode api -------------------------
func (n *BoxInode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	// log.Debug("Getatt:", n.Path())

	if n.Name != "" && !CheckAllowProcess("Getattr", ctx) {
		return fs.ToErrno(os.ErrNotExist)
	}

	n.Attr.GetToFuse(&out.Attr)

	return fs.OK
}

func (n *BoxInode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	log.Debug("Setattr:", n.Path())

	if !CheckAllowProcess("Setattr", ctx) {
		if n.Name == "" {
			return fs.ToErrno(os.ErrPermission)
		} else {
			return fs.ToErrno(os.ErrNotExist)
		}
	}

	n.Attr.SetFromAttrIn(in)

	if sz, ok := in.GetSize(); ok {
		if fh, fok := f.(*BoxFile); fok {
			log.Warn("Truncate:", n.Path(), "|", sz)
			if sz <= uint64(len(fh.data)) {
				fh.data = fh.data[0:sz]
			} else {
				pading := bytes.Repeat([]byte{byte(0)}, int(sz)-len(fh.data))
				fh.data = append(fh.data, pading...)
			}
			fserr := fh.Fsync(ctx, 0)
			if fserr != fs.OK {
				return fserr
			}
		}
	}

	n.Attr.GetToFuse(&out.Attr)
	err := n.UpdateToDB()
	if err != nil {
		return fs.ToErrno(os.ErrInvalid)
	}
	return fs.OK
}

func (n *BoxInode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	log.Debug("Mkdir:", n.Path(), "/", name)

	if !CheckAllowProcess("Mkdir", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}

	caller, ok := fuse.FromContext(ctx)
	if !ok {
		log.Error("Getattr FromContext error")
		return nil, fs.ToErrno(os.ErrInvalid)
	}

	box := n.AddChildNode(name)
	box.Name = name
	box.Attr.Atime = time.Now()
	box.Attr.Ctime = time.Now()
	box.Attr.Mtime = time.Now()
	box.Attr.Uid = caller.Uid
	box.Attr.Gid = caller.Gid
	box.Attr.Mode = 0755 | syscall.S_IFDIR

	sa := fs.StableAttr{}
	sa.Mode = box.Attr.Mode
	sa.Ino = box.Attr.Ino
	b := n.Inode.NewInode(ctx, box, sa)

	box.Attr.GetToFuse(&out.Attr)

	err := n.UpdateToDB()
	if err != nil {
		return nil, fs.ToErrno(os.ErrInvalid)
	}
	return b, fs.OK
}

func (n *BoxInode) Rmdir(ctx context.Context, name string) syscall.Errno {
	log.Debug("Rmdir:", n.Path(), "/", name)

	if !CheckAllowProcess("Rmdir", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}

	n.DelChildNode(name)

	err := n.UpdateToDB()
	if err != nil {
		return fs.ToErrno(os.ErrInvalid)
	}
	return fs.OK
}
func (n *BoxInode) Unlink(ctx context.Context, name string) syscall.Errno {
	log.Debug("Unlink:", n.Path(), "/", name)

	if !CheckAllowProcess("Unlink", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}

	isDir := n.IsDir()

	// TODO:Transaction
	n.DelChildNode(name)
	err := n.UpdateToDB()
	if err != nil {
		return fs.ToErrno(os.ErrInvalid)
	}
	if !isDir {
		GetDBInstance().Del([]byte(n.Path()))
	}
	return fs.OK
}

func (n *BoxInode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	log.Debug("Rename:", name, "|", newName)

	if !CheckAllowProcess("Rename", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}

	c, err := n.GetChildNode(name)
	if err != nil {
		log.Error("Rename: src not exist ", err)
		return fs.ToErrno(err)
	}
	oldPath := c.Path()

	n.DelChildNode(name)
	c.Name = newName
	node, ok := newParent.(*BoxInode)
	if !ok {
		log.Error("Rename: InodeEmbedder error")
		return fs.ToErrno(os.ErrInvalid)
	}
	node.AddExistChildNode(newName, c)
	newPath := c.Path()

	if !c.IsDir() {
		log.Debug("RenameFile:", oldPath, "->", newPath)
		data, err := GetDBInstance().Get([]byte(oldPath))
		if err != nil {
			log.Error("rename file not exist:", err)
			return fs.ToErrno(err)
		}
		err = GetDBInstance().Del([]byte(oldPath))
		if err != nil {
			log.Error("rename del file failed:", err)
			return fs.ToErrno(err)
		}
		err = GetDBInstance().Set([]byte(newPath), data)
		if err != nil {
			log.Error("rename set file failed:", err)
			return fs.ToErrno(err)
		}
	} else {
		log.Debug("RenameDir:", oldPath, "->", newPath)
	}

	err = n.UpdateToDB()
	if err != nil {
		return fs.ToErrno(os.ErrInvalid)
	}

	return fs.ToErrno(err)
}

func (n *BoxInode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	log.Debug("Lookup:", n.Path(), "/", name)

	if !CheckAllowProcess("Lookup", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}

	if n.ChildrenNode == nil {
		log.Warn("Lookup: children not exist ", n.Path(), "/", name)
		return nil, fs.ToErrno(os.ErrNotExist)
	}

	for k, v := range n.ChildrenNode {
		if k == name {
			sa := fs.StableAttr{}
			sa.Mode = v.Attr.Mode
			sa.Ino = v.Attr.Ino
			v.Attr.GetToFuse(&out.Attr)

			// log.Debug("Lookup Attr()", v.Path(), ",", out.Attr.Mode, "|", v.Attr.Mode)
			b := n.Inode.NewInode(ctx, v, sa)
			return b, fs.OK
		}
	}

	log.Warn("Lookup: children not found ", n.Path(), "/", name)
	return nil, fs.ToErrno(os.ErrNotExist)
}

func (n *BoxInode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	log.Debug("Readdir:", n.Path(), "|", len(n.ChildrenNode))

	if !CheckAllowProcess("Readdir", ctx) {
		return &DirEntryReader{}, fs.OK
	}

	r := DirEntryReader{}
	for _, v := range n.ChildrenNode {
		dir := fuse.DirEntry{}
		dir.Ino = v.Attr.Ino
		dir.Mode = v.Attr.Mode
		dir.Name = v.Name
		r.dirs = append(r.dirs, dir)
	}
	// log.Debug("Readdir() --- ", r)
	return &r, fs.OK
}

func (n *BoxInode) String() string {
	return fmt.Sprint("Name:", n.Path(), ", Attr=", n.Attr)
}

func (n *BoxInode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	log.Debug("Create:", n.Path(), "/", name)

	if !CheckAllowProcess("Create", ctx) {
		return nil, nil, 0, fs.ToErrno(os.ErrPermission)
	}

	// TODO:flags
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		log.Error("Getattr FromContext error")
		return nil, nil, 0, fs.ToErrno(os.ErrInvalid)
	}

	box := n.AddChildNode(name)
	box.Name = name
	box.Attr.Atime = time.Now()
	box.Attr.Ctime = time.Now()
	box.Attr.Mtime = time.Now()
	box.Attr.Uid = caller.Uid
	box.Attr.Gid = caller.Gid
	box.Attr.Mode = 0644

	sa := fs.StableAttr{}
	sa.Mode = box.Attr.Mode
	sa.Ino = box.Attr.Ino
	b := n.Inode.NewInode(ctx, box, sa)

	box.Attr.GetToFuse(&out.Attr)

	bfile := &BoxFile{}
	bfile.inode = box
	bfile.data = []byte("")

	err := n.UpdateToDB()
	if err != nil {
		return nil, nil, 0, fs.ToErrno(os.ErrInvalid)
	}
	return b, bfile, 0, fs.OK
}

func (n *BoxInode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	// TODO:flags
	log.Debug("Open:", n.Path())

	if !CheckAllowProcess("Open", ctx) {
		return 0, 0, fs.ToErrno(os.ErrPermission)
	}

	bfile := &BoxFile{}
	bfile.inode = n

	data, err := GetDBInstance().Get([]byte(n.Path()))
	if err != nil {
		log.Error("Read DB failed:", err)
		return 0, 0, fs.ToErrno(os.ErrInvalid)
	}

	bfile.data = data

	return bfile, flags, fs.OK
}

func (n *BoxInode) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	// TODO: Write cache, persist when sync
	return fs.OK
}

// ==============================================================================================

type BoxFile struct {
	inode *BoxInode
	data  []byte
}

func (f *BoxFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	// TODO: read cache
	log.Debug("Read:", f.inode.Path(), "|", off, "|", len(dest), "|", len(f.data))

	if !CheckAllowProcess("Read", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}

	end := 0
	data := []byte("")
	if off < int64(len(f.data)) {
		end = int(off) + len(dest)
		if end > len(f.data) {
			end = len(f.data)
		}
		data = f.data[off:end]
	}

	// log.Debug("Read()", len(data))
	res := &readResult{data}

	return res, fs.OK
}

func (f *BoxFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	err := GetDBInstance().Set([]byte(f.inode.Path()), f.data)
	if err != nil {
		log.Error("Write DB failed:", err)
		return fs.ToErrno(os.ErrInvalid)
	}
	return fs.OK
}

func (f *BoxFile) Write(ctx context.Context, data []byte, off int64) (written uint32, errno syscall.Errno) {
	log.Debug("Write:", f.inode.Path(), "|", off, "|", len(data), "|", len(f.data))

	if !CheckAllowProcess("Write", ctx) {
		return 0, fs.ToErrno(os.ErrPermission)
	}

	if int64(len(f.data)) < off {
		log.Errorf("Write: plain(%d) < off(%d)", len(f.data), off)
		return 0, fs.ToErrno(os.ErrInvalid)
	}

	if off+int64(len(data)) > int64(len(f.data)) {
		f.data = append(f.data[0:off], data...)
	} else {
		for i := 0; i < len(data); i++ {
			f.data[off+int64(i)] = data[i]
		}
	}

	fserr := f.Fsync(ctx, 0)
	if fserr != fs.OK {
		return 0, fserr
	}

	// TODO:Transaction
	f.inode.Attr.Size = uint64(len(f.data))
	err := f.inode.UpdateToDB()
	if err != nil {
		return uint32(len(data)), fs.ToErrno(err)
	}
	return uint32(len(data)), fs.OK
}
