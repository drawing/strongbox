package securefs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
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

	return root.NewNode(nil, "", &st), nil
}

type SecureLoopbackRoot struct {
	fs.LoopbackRoot
}

func (r *SecureLoopbackRoot) NewNode(parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
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

func (n *SecureLoopbackNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
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
