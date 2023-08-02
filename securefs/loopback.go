package securefs

import (
	"context"
	"os"
	"path/filepath"

	// "runtime/debug"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	log "github.com/sirupsen/logrus"
)

func NewSecureLoopbackRoot(rootPath string) (fs.InodeEmbedder, error) {
	var st syscall.Stat_t
	err := syscall.Stat(rootPath, &st)
	if err != nil {
		return nil, err
	}

	root := &SecureLoopbackRoot{
		LoopbackRoot: fs.LoopbackRoot{
			Path: rootPath,
			Dev:  uint64(st.Dev),
		},
	}
	root.LoopbackRoot.NewNode = root.HookNewNode

	return root.HookNewNode(&root.LoopbackRoot, nil, "", &st), nil
}

type SecureLoopbackRoot struct {
	fs.LoopbackRoot
}

func (r *SecureLoopbackRoot) HookNewNode(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
	log.Debug("Hook NewNode:", name)

	return &SecureLoopbackNode{
		LoopbackNode: fs.LoopbackNode{
			RootData: &r.LoopbackRoot,
		},
		RootData: r,
	}
}

func (r *SecureLoopbackRoot) NewNode(parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
	log.Debug("NewNode:", name)
	return &SecureLoopbackNode{
		LoopbackNode: fs.LoopbackNode{
			RootData: &r.LoopbackRoot,
		},
		RootData: r,
	}
}

func (r *SecureLoopbackRoot) IdFromStat(st *syscall.Stat_t) fs.StableAttr {
	// We compose an inode number by the underlying inode, and
	// mixing in the device number. In traditional filesystems,
	// the inode numbers are small. The device numbers are also
	// small (typically 16 bit). Finally, we mask out the root
	// device number of the root, so a loopback FS that does not
	// encompass multiple mounts will reflect the inode numbers of
	// the underlying filesystem
	swapped := (uint64(st.Dev) << 32) | (uint64(st.Dev) >> 32)
	swappedRootDev := (r.Dev << 32) | (r.Dev >> 32)
	return fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		// This should work well for traditional backing FSes,
		// not so much for other go-fuse FS-es
		Ino: (swapped ^ swappedRootDev) ^ st.Ino,
	}
}

type SecureLoopbackNode struct {
	fs.LoopbackNode

	RootData *SecureLoopbackRoot
}

func (n *SecureLoopbackNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	if !CheckAllowProcess("Statfs", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Statfs(ctx, out)
}

func (n *SecureLoopbackNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !CheckAllowProcess("Lookup", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}

	return n.LoopbackNode.Lookup(ctx, name, out)
}
func (n *SecureLoopbackNode) Mknod(ctx context.Context, name string, mode, rdev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !CheckAllowProcess("Mknod", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Mknod(ctx, name, mode, rdev, out)
}
func (n *SecureLoopbackNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !CheckAllowProcess("Mkdir", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Mkdir(ctx, name, mode, out)
}
func (n *SecureLoopbackNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if !CheckAllowProcess("Mkdir", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Rmdir(ctx, name)
}
func (n *SecureLoopbackNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if !CheckAllowProcess("Unlink", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}
	log.Debugf("Unlink: %s %s", n.Path(), name)
	return n.LoopbackNode.Unlink(ctx, name)
}
func (n *SecureLoopbackNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if !CheckAllowProcess("Rename", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
}
func (n *SecureLoopbackNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !CheckAllowProcess("Symlink", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Symlink(ctx, target, name, out)
}
func (n *SecureLoopbackNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !CheckAllowProcess("Link", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Link(ctx, target, name, out)
}
func (n *SecureLoopbackNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if !CheckAllowProcess("Readlink", ctx) {
		return nil, fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Readlink(ctx)
}
func (n *SecureLoopbackNode) Opendir(ctx context.Context) syscall.Errno {
	// TODO fake
	if !CheckAllowProcess("Opendir", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}
	return n.LoopbackNode.Opendir(ctx)
}

type emptyDir struct {
}

func (e *emptyDir) HasNext() bool {
	return false
}
func (e *emptyDir) Next() (fuse.DirEntry, syscall.Errno) {
	return fuse.DirEntry{}, fs.ToErrno(os.ErrNotExist)
}
func (e *emptyDir) Close() {}

func (n *SecureLoopbackNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	// TODO fake
	if !CheckAllowProcess("Readdir", ctx) {
		// return nil, fs.ToErrno(os.ErrPermission)
		return &emptyDir{}, fs.OK
	}
	return n.LoopbackNode.Readdir(ctx)
}

func (n *SecureLoopbackNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if !CheckAllowProcess("Getattr", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}
	// log.Info("node Getattr: path=", n.Path(), ", f=", f)
	// debug.PrintStack()
	syserr := n.LoopbackNode.Getattr(ctx, f, out)
	if syserr != fs.OK {
		return syserr
	}

	if out.Mode&syscall.S_IFDIR == 0 {
		// log.Info("node Getattr: path is file, start change size ", n.Path(), ", f=", f)
		fd, err := syscall.Open(n.Path(), os.O_RDONLY, 0)
		if err != nil {
			return fs.ToErrno(err)
		}

		buffer := make([]byte, 4)

		readN, err := syscall.Pread(int(fd), buffer, 0)
		if err != nil || readN < 4 {
			return fs.OK
		} else {
			out.Size = uint64(bytesToInt(buffer))
			log.Debugf("change size %s %d", n.Path(), out.Size)
		}

		syscall.Close(fd)
	}

	return syserr
}

func (n *SecureLoopbackNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if !CheckAllowProcess("Setattr", ctx) {
		return fs.ToErrno(os.ErrPermission)
	}
	log.Info("node Setattr: path=", n.Path(), ", f=", f)
	// debug.PrintStack()
	return n.LoopbackNode.Setattr(ctx, f, in, out)
}

func (n *SecureLoopbackNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	if !CheckAllowProcess("Create", ctx) {
		return nil, nil, 0, fs.ToErrno(os.ErrPermission)
	}

	p := filepath.Join(n.Path(), name)
	flags = flags &^ syscall.O_APPEND
	fd, err := syscall.Open(p, int(flags)|os.O_CREATE, mode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	n.PreserveOwner(ctx, p)
	st := syscall.Stat_t{}
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, nil, 0, fs.ToErrno(err)
	}

	node := n.RootData.NewNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.IdFromStat(&st))
	lf := NewSecureLoopbackFile(fd)

	out.FromStat(&st)
	return ch, lf, 0, 0
}

func (n *SecureLoopbackNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	if !CheckAllowProcess("Open", ctx) {
		return nil, 0, fs.ToErrno(os.ErrPermission)
	}
	flags = flags &^ syscall.O_APPEND
	p := n.Path()
	f, err := syscall.Open(p, int(flags), 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	lf := NewSecureLoopbackFile(f)
	return lf, 0, 0
}

func (n *SecureLoopbackNode) Path() string {
	path := n.LoopbackNode.Path(n.Root())
	return filepath.Join(n.RootData.Path, path)
}

func (n *SecureLoopbackNode) PreserveOwner(ctx context.Context, path string) error {
	if os.Getuid() != 0 {
		return nil
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil
	}
	return syscall.Lchown(path, int(caller.Uid), int(caller.Gid))
}
