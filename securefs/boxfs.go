package securefs

import (
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
	if in.Size > 0 {
		a.Size = in.Size
	}
	if in.Atime > 0 {
		a.Atime = time.Unix(int64(in.Atime), int64(in.Atimensec))
	}
	if in.Mtime > 0 {
		a.Mtime = time.Unix(int64(in.Mtime), int64(in.Mtimensec))
	}
	// a.Ctime = time.Unix(int64(in.Ctime), int64(in.Ctimensec))
	a.Mode = in.Mode
	a.Uid = in.Uid
	a.Gid = in.Gid
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

func (n *BoxInode) DelChildNode(name string) {
	if n.ChildrenNode == nil {
		return
	}
	delete(n.ChildrenNode, name)
}

func (n *BoxInode) RenameChildNode(src string, dst string) error {
	if n.ChildrenNode == nil {
		return os.ErrNotExist
	}
	c, ok := n.ChildrenNode[src]
	if !ok {
		return os.ErrNotExist
	}
	delete(n.ChildrenNode, src)
	c.Name = dst
	n.ChildrenNode[dst] = c
	return nil
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

	// log.Println("LOAD_DB:", b)

	return nil
}

func (n *BoxInode) Path() string {
	// TODO
	var c *BoxInode = n
	path := c.Name
	c = c.parent
	for c != nil {
		path = c.Name + "/" + path
		c = c.parent
	}
	return path
}

// ------- fs api --------
func (n *BoxInode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.Attr.GetToFuse(&out.Attr)
	log.Debug("Getattr()", n.Path(), ", ", out.Attr.Mode)
	return fs.OK
}

func (n *BoxInode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	log.Debug("Setattr()", n.Path(), ", ", in, ", ", out, ", ", in.Valid)
	// TODO
	// n.Attr.SetFromAttrIn(in)
	n.Attr.GetToFuse(&out.Attr)
	err := n.UpdateToDB()
	if err != nil {
		return fs.ToErrno(os.ErrInvalid)
	}
	return fs.OK
}

func (n *BoxInode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	log.Debug("Mkdir()", name)

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
	log.Debug("Rmdir()", name, ", ", n.Name)
	n.DelChildNode(name)

	err := n.UpdateToDB()
	if err != nil {
		return fs.ToErrno(os.ErrInvalid)
	}
	return fs.OK
}
func (n *BoxInode) Unlink(ctx context.Context, name string) syscall.Errno {
	log.Debug("Unlink()", name, ", ", n.Name)
	isDir := n.IsDir()

	// TODO Transaction
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
	// TODO
	log.Debug("Rename()", name, ", ", n.Name)
	err := n.RenameChildNode(name, newName)
	if err != nil {
		return fs.ToErrno(err)
	}
	err = n.UpdateToDB()
	if err != nil {
		return fs.ToErrno(os.ErrInvalid)
	}

	return fs.ToErrno(err)
}

func (n *BoxInode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	log.Debug("Lookup()", name, ",", n.Name, "|", n.ChildrenNode)

	if n.ChildrenNode == nil {
		return nil, fs.ToErrno(os.ErrNotExist)
	}

	for k, v := range n.ChildrenNode {
		if k == name {
			sa := fs.StableAttr{}
			sa.Mode = v.Attr.Mode
			sa.Ino = v.Attr.Ino
			v.Attr.GetToFuse(&out.Attr)

			log.Debug("Lookup Attr()", v.Path(), ",", out.Attr.Mode, "|", v.Attr.Mode)
			b := n.Inode.NewInode(ctx, v, sa)
			return b, fs.OK
		}
	}

	return nil, fs.ToErrno(os.ErrNotExist)
}

/*
func (n *BoxInode) Opendir(ctx context.Context) syscall.Errno {
	log.Debug("Opendir()")
	return fs.OK
}
*/

type DirEntryReader struct {
	index int
	dirs  []fuse.DirEntry
}

func (d *DirEntryReader) HasNext() bool {
	if d.index < len(d.dirs) {
		return true
	}
	return false
}
func (d *DirEntryReader) Next() (fuse.DirEntry, syscall.Errno) {
	if d.index >= len(d.dirs) {
		return fuse.DirEntry{}, fs.ToErrno(os.ErrInvalid)
	}
	dir := d.dirs[d.index]
	d.index++
	return dir, fs.OK
}
func (d *DirEntryReader) Close() {
}

func (n *BoxInode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	log.Debug("Readdir()", n.Name, ", ", len(n.ChildrenNode))
	r := DirEntryReader{}
	for _, v := range n.ChildrenNode {
		dir := fuse.DirEntry{}
		dir.Ino = v.Attr.Ino
		dir.Mode = v.Attr.Mode
		dir.Name = v.Name
		r.dirs = append(r.dirs, dir)
	}
	log.Debug("Readdir() --- ", r)
	return &r, fs.OK
}

func (n *BoxInode) String() string {
	return fmt.Sprint("Name:", n.Name, ", Attr=", n.Attr)
}

func (n *BoxInode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	log.Debug("Create()", n.Name, ", ", len(n.ChildrenNode))
	// TODO flags

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
	// TODO flags
	log.Debug("Open()", n.Name, ", ", n)
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

/*
func (n *BoxInode) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	log.Debug("Node Read()", n.Name)
	return nil, fs.ToErrno(os.ErrInvalid)
}
*/

// ==============================================================================================

type BoxFile struct {
	inode *BoxInode
	data  []byte
}

func (f *BoxFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	// TODO read cache
	log.Debug("Read()", f.inode.Name, ", ", len(f.data))

	start := 0
	end := 0
	data := []byte("")
	if off < int64(len(f.data)) {
		end = int(off) + len(f.data)
		if end > len(f.data) {
			end = len(f.data)
		}
		data = f.data[start:end]
	}

	log.Debug("Read()", string(data))
	res := &readResult{data}

	return res, fs.OK
}

func (f *BoxFile) Write(ctx context.Context, data []byte, off int64) (written uint32, errno syscall.Errno) {
	log.Debug("Write()", f.inode.Name)

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

	// TODO Transaction
	err := GetDBInstance().Set([]byte(f.inode.Path()), f.data)
	if err != nil {
		log.Error("Write DB failed:", err)
		return 0, fs.ToErrno(os.ErrInvalid)
	}

	f.inode.Attr.Size = uint64(len(f.data))
	err = f.inode.UpdateToDB()
	if err != nil {
		return uint32(len(data)), fs.ToErrno(err)
	}
	return uint32(len(data)), fs.OK
}

// ==============================================================================================
/*
func (n *BoxInode) IsDir() bool {
	log.Error("IsDir()", n.Name, ", ", n.Attr.Mode&syscall.S_IFDIR != 0)

	return n.Attr.Mode&syscall.S_IFDIR != 0
}
*/
/*
// StableAttr returns the (Ino, Gen) tuple for this node.
func (n *BoxInode) StableAttr() fs.StableAttr {
	log.Error("StableAttr()")
	return fs.StableAttr{}
}

// Mode returns the filetype
func (n *BoxInode) Mode() uint32 {
	log.Error("Mode()")
	return 0755
}

// Returns the root of the tree
func (n *BoxInode) Root() *fs.Inode {
	log.Error("Root()")
	return nil
}

// Returns whether this is the root of the tree
func (n *BoxInode) IsRoot() bool {
	log.Error("IsRoot()")
	return true
}

// Forgotten returns true if the kernel holds no references to this
// inode.  This can be used for background cleanup tasks, since the
// kernel has no way of reviving forgotten nodes by its own
// initiative.
func (n *BoxInode) Forgotten() bool {
	log.Error("Forgotten()")
	return false
}

// Operations returns the object implementing the file system
// operations.
func (n *BoxInode) Operations() fs.InodeEmbedder {
	log.Error("Operations()")
	return nil
}

// NewPersistentInode returns an Inode whose lifetime is not in
// control of the kernel.
//
// When the kernel is short on memory, it will forget cached file
// system information (directory entries and inode metadata). This is
// announced with FORGET messages.  There are no guarantees if or when
// this happens. When it happens, these are handled transparently by
// go-fuse: all Inodes created with NewInode are released
// automatically. NewPersistentInode creates inodes that go-fuse keeps
// in memory, even if the kernel is not interested in them. This is
// convenient for building static trees up-front.
func (n *BoxInode) NewPersistentInode(ctx context.Context, node fs.InodeEmbedder, id fs.StableAttr) *fs.Inode {
	log.Error("NewPersistentInode()")
	return n.newInode(ctx, node, id, true)
}

// ForgetPersistent manually marks the node as no longer important. If
// it has no children, and if the kernel as no references, the nodes
// gets removed from the tree.
func (n *BoxInode) ForgetPersistent() {
	log.Error("ForgetPersistent()")
}

// NewInode returns an inode for the given InodeEmbedder. The mode
// should be standard mode argument (eg. S_IFDIR). The inode number in
// id.Ino argument is used to implement hard-links.  If it is given,
// and another node with the same ID is known, the new inode may be
// ignored, and the old one used instead.
func (n *BoxInode) NewInode(ctx context.Context, node fs.InodeEmbedder, id fs.StableAttr) *fs.Inode {
	log.Error("NewInode()")
	return n.newInode(ctx, node, id, false)
}

func (n *BoxInode) newInode(ctx context.Context, ops fs.InodeEmbedder, id fs.StableAttr, persistent bool) *fs.Inode {
	log.Error("newInode()")
	return nil
}

// GetChild returns a child node with the given name, or nil if the
// directory has no child by that name.
func (n *BoxInode) GetChild(name string) *fs.Inode {
	log.Error("GetChild()")
	return nil
}

// AddChild adds a child to this node. If overwrite is false, fail if
// the destination already exists.
func (n *BoxInode) AddChild(name string, ch *fs.Inode, overwrite bool) (success bool) {
	log.Error("AddChild()")
	return false
}

// Children returns the list of children of this directory Inode.
func (n *BoxInode) Children() map[string]*fs.Inode {
	log.Error("Children()")
	return nil
}

// Parents returns a parent of this Inode, or nil if this Inode is
// deleted or is the root
func (n *BoxInode) Parent() (string, *fs.Inode) {
	log.Error("Parent()")
	return "", nil
}

// RmAllChildren recursively drops a tree, forgetting all persistent
// nodes.
func (n *BoxInode) RmAllChildren() {
	log.Debug("RmAllChildren()")
}

// RmChild removes multiple children.  Returns whether the removal
// succeeded and whether the node is still live afterward. The removal
// is transactional: it only succeeds if all names are children, and
// if they all were removed successfully.  If the removal was
// successful, and there are no children left, the node may be removed
// from the FS tree. In that case, RmChild returns live==false.
func (n *BoxInode) RmChild(names ...string) (success, live bool) {
	log.Error("RmChild()")
	return false, false
}

// MvChild executes a rename. If overwrite is set, a child at the
// destination will be overwritten, should it exist. It returns false
// if 'overwrite' is false, and the destination exists.
func (n *BoxInode) MvChild(old string, newParent *fs.Inode, newName string, overwrite bool) bool {
	log.Error("MvChild()")
	return false
}

// ExchangeChild swaps the entries at (n, oldName) and (newParent,
// newName).
func (n *BoxInode) ExchangeChild(oldName string, newParent *fs.Inode, newName string) {
	log.Error("ExchangeChild()")
}

// NotifyEntry notifies the kernel that data for a (directory, name)
// tuple should be invalidated. On next access, a LOOKUP operation
// will be started.
func (n *BoxInode) NotifyEntry(name string) syscall.Errno {
	log.Error("NotifyEntry()")
	return fs.ToErrno(os.ErrPermission)
}

// NotifyDelete notifies the kernel that the given inode was removed
// from this directory as entry under the given name. It is equivalent
// to NotifyEntry, but also sends an event to inotify watchers.
func (n *BoxInode) NotifyDelete(name string, child *fs.Inode) syscall.Errno {
	log.Error("NotifyDelete()")
	// XXX arg ordering?
	return fs.ToErrno(os.ErrPermission)
}

// NotifyContent notifies the kernel that content under the given
// inode should be flushed from buffers.
func (n *BoxInode) NotifyContent(off, sz int64) syscall.Errno {
	log.Error("NotifyContent()")
	// XXX how does this work for directories?
	return fs.ToErrno(os.ErrPermission)
}

// WriteCache stores data in the kernel cache.
func (n *BoxInode) WriteCache(offset int64, data []byte) syscall.Errno {
	log.Error("WriteCache()")
	return fs.ToErrno(os.ErrPermission)
}

// ReadCache reads data from the kernel cache.
func (n *BoxInode) ReadCache(offset int64, dest []byte) (count int, errno syscall.Errno) {
	log.Error("ReadCache()")
	return 0, fs.ToErrno(os.ErrPermission)
}
*/
