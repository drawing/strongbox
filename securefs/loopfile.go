package securefs

import (
	"bytes"
	"context"
	"os"
	"sync"
	"syscall"

	cfg "strongbox/configuration"

	log "github.com/sirupsen/logrus"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// NewLoopbackFile creates a FileHandle out of a file descriptor. All
// operations are implemented. When using the Fd from a *os.File, call
// syscall.Dup() on the fd, to avoid os.File's finalizer from closing
// the file descriptor.
func NewSecureLoopbackFile(fd int) fs.FileHandle {
	// log.Debugf("NewFile: fd=%d", fd)
	lf := &loopbackFile{fd: fd}
	lf.plainData = nil
	lf.cipherData = nil
	lf.load()
	return lf
}

func (f *loopbackFile) load() syscall.Errno {
	var attr fuse.AttrOut
	fserr := f.getattr(&attr)
	if fserr != fs.OK {
		log.Error("Load: getattr error ", fserr)
		return fserr
	}

	if attr.Size == 0 || attr.Size <= 4 {
		f.plainData = []byte("")
		f.cipherData = f.plainData
		return fs.OK
	}

	buffer := make([]byte, attr.Size)
	readN, err := syscall.Pread(int(f.fd), buffer, 0)
	if err != nil {
		log.Errorf("Load: empty %d-%d-%s", attr.Size, readN, err.Error())
		f.plainData = []byte("")
		f.cipherData = f.plainData
		return fs.OK
	}
	if readN < 4 {
		return fs.ToErrno(os.ErrInvalid)
	}
	/*
		if err != nil {
			log.Error("Load: pread error ", err)
			return fs.ToErrno(err)
		}
	*/
	if readN < len(buffer) {
		buffer = buffer[0:readN]
	}

	f.cipherData = buffer[4:]

	// TODO
	iv := []byte("1234567887654321")

	// log.Debug("Load: decrypt ", len(f.cipherData))
	plain, err := AESDecrypt(f.cipherData, cfg.Cfg.SecretKey, iv)
	if err != nil {
		log.Error("Load: decrypt error ", err)
		return fs.ToErrno(err)
	}

	f.plainData = plain
	return fs.OK
}

func (f *loopbackFile) save() syscall.Errno {
	// TODO
	iv := []byte("1234567887654321")

	// log.Debug("save plainData:", string(f.plainData))
	var err error
	f.cipherData, err = AESEncrypt(f.plainData, cfg.Cfg.SecretKey, iv)
	if err != nil {
		log.Error("Save: encrypt error ", err)
		return fs.ToErrno(err)
	}

	// log.Debug("save cipherData:", base64.StdEncoding.EncodeToString(f.cipherData))

	buf := intToBytes(len(f.plainData))
	_, err = syscall.Pwrite(f.fd, buf, 0)
	if err != nil {
		log.Error("Save: pwrite error ", err)
		return fs.ToErrno(err)
	}

	_, err = syscall.Pwrite(f.fd, f.cipherData, 4)
	if err != nil {
		log.Error("Save: pwrite error ", err)
		return fs.ToErrno(err)
	}

	return fs.OK
}

type loopbackFile struct {
	mu sync.Mutex
	fd int

	plainData  []byte
	cipherData []byte
}

type readResult struct {
	content []byte
}

func (r *readResult) Bytes(buf []byte) ([]byte, fuse.Status) {
	return r.content, fuse.OK
}

func (r *readResult) Size() int {
	return len(r.content)
}

func (r *readResult) Done() {
	r.content = []byte("")
}

func (f *loopbackFile) Read(ctx context.Context, buf []byte, off int64) (res fuse.ReadResult, errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	log.Warnf("Read: buf_len=%d off=%d", len(buf), off)

	if f.plainData == nil {
		log.Errorf("Read: plainData=nil")
		return nil, fs.ToErrno(os.ErrInvalid)
	}

	newData := []byte("")
	if off < int64(len(f.plainData)) {
		end := off + int64(len(buf))
		if end > int64(len(f.plainData)) {
			end = int64(len(f.plainData))
		}
		newData = f.plainData[off:end]
	}
	// log.Debugf("read plain:%d-%d, %s-%s", len(f.plainData), len(newData), string(f.plainData), string(newData))

	res = &readResult{newData}
	return res, fs.OK
}

func (f *loopbackFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	log.Debugf("Write: data_len=%d off=%d", len(data), off)

	if f.plainData == nil {
		log.Errorf("Write: plainData==nil")
		return 0, fs.ToErrno(os.ErrInvalid)
	}

	if int64(len(f.plainData)) < off {
		log.Errorf("Write: plain(%d) < off(%d)", len(f.plainData), off)
		return 0, fs.ToErrno(os.ErrInvalid)
	}

	if off+int64(len(data)) > int64(len(f.plainData)) {
		f.plainData = append(f.plainData[0:off], data...)
	} else {
		for i := 0; i < len(data); i++ {
			f.plainData[off+int64(i)] = data[i]
		}
	}

	// log.Debugf("write plain:%d-%d, %s-%s", len(f.plainData), len(data), string(f.plainData), string(data))

	fserr := f.save()
	if fserr != fs.OK {
		log.Errorf("Write: save error")
		return 0, fserr
	}

	return uint32(len(data)), fs.OK
}

func (f *loopbackFile) Release(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	log.Debug("call file Release")
	if f.fd != -1 {
		err := syscall.Close(f.fd)
		f.fd = -1
		return fs.ToErrno(err)
	}
	return syscall.EBADF
}

func (f *loopbackFile) Flush(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	log.Debug("call file Flush")
	// Since Flush() may be called for each dup'd fd, we don't
	// want to really close the file, we just want to flush. This
	// is achieved by closing a dup'd fd.
	newFd, err := syscall.Dup(f.fd)

	if err != nil {
		return fs.ToErrno(err)
	}
	err = syscall.Close(newFd)
	return fs.ToErrno(err)
}

func (f *loopbackFile) Fsync(ctx context.Context, flags uint32) (errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := fs.ToErrno(syscall.Fsync(f.fd))

	return r
}

const (
	_OFD_GETLK  = 36
	_OFD_SETLK  = 37
	_OFD_SETLKW = 38
)

func (f *loopbackFile) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) (errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	log.Debug("call file Getlk")

	flk := syscall.Flock_t{}
	lk.ToFlockT(&flk)
	errno = fs.ToErrno(syscall.FcntlFlock(uintptr(f.fd), _OFD_GETLK, &flk))
	out.FromFlockT(&flk)
	return
}

func (f *loopbackFile) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) (errno syscall.Errno) {
	log.Debug("call file Setlk")

	return f.setLock(ctx, owner, lk, flags, false)
}

func (f *loopbackFile) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) (errno syscall.Errno) {
	log.Debug("call file Setlkw")

	return f.setLock(ctx, owner, lk, flags, true)
}

func (f *loopbackFile) setLock(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, blocking bool) (errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if (flags & fuse.FUSE_LK_FLOCK) != 0 {
		var op int
		switch lk.Typ {
		case syscall.F_RDLCK:
			op = syscall.LOCK_SH
		case syscall.F_WRLCK:
			op = syscall.LOCK_EX
		case syscall.F_UNLCK:
			op = syscall.LOCK_UN
		default:
			return syscall.EINVAL
		}
		if !blocking {
			op |= syscall.LOCK_NB
		}
		return fs.ToErrno(syscall.Flock(f.fd, op))
	} else {
		flk := syscall.Flock_t{}
		lk.ToFlockT(&flk)
		var op int
		if blocking {
			op = _OFD_SETLKW
		} else {
			op = _OFD_SETLK
		}
		return fs.ToErrno(syscall.FcntlFlock(uintptr(f.fd), op, &flk))
	}
}

func (f *loopbackFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	log.Debug("call file Setattr")

	if errno := f.setAttr(ctx, in); errno != 0 {
		return errno
	}

	return f.Getattr(ctx, out)
}

func (f *loopbackFile) fchmod(mode uint32) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	log.Debug("call file fchmod")
	return fs.ToErrno(syscall.Fchmod(f.fd, mode))
}

func (f *loopbackFile) fchown(uid, gid int) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	log.Debug("call file fchown")
	return fs.ToErrno(syscall.Fchown(f.fd, uid, gid))
}

func (f *loopbackFile) ftruncate(sz uint64) syscall.Errno {
	log.Debug("call file ftruncate: ", sz)

	if uint64(len(f.plainData)) >= sz {
		f.plainData = f.plainData[0:sz]
	} else {
		padtext := bytes.Repeat([]byte{byte(0)}, int(sz)-len(f.plainData))
		f.plainData = append(f.plainData, padtext...)
	}
	fserr := f.save()
	if fserr != fs.OK {
		log.Error("ftruncate: ", fserr)
		return fserr
	}
	return fs.OK
	// return fs.ToErrno(syscall.Ftruncate(f.fd, int64(sz)))
}

func (f *loopbackFile) setAttr(ctx context.Context, in *fuse.SetAttrIn) syscall.Errno {
	// var errno syscall.Errno
	if mode, ok := in.GetMode(); ok {
		if errno := f.fchmod(mode); errno != 0 {
			return errno
		}
	}

	uid32, uOk := in.GetUID()
	gid32, gOk := in.GetGID()
	if uOk || gOk {
		uid := -1
		gid := -1

		if uOk {
			uid = int(uid32)
		}
		if gOk {
			gid = int(gid32)
		}
		if errno := f.fchown(uid, gid); errno != 0 {
			return errno
		}
	}
	/*
		mtime, mok := in.GetMTime()
		atime, aok := in.GetATime()

		if mok || aok {
			ap := &atime
			mp := &mtime
			if !aok {
				ap = nil
			}
			if !mok {
				mp = nil
			}
			errno = f.utimens(ap, mp)
			if errno != 0 {
				return errno
			}
		}
	*/
	if sz, ok := in.GetSize(); ok {
		if errno := f.ftruncate(sz); errno != 0 {
			return errno
		}
	}
	return fs.OK
}

func (f *loopbackFile) Getattr(ctx context.Context, a *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()

	fserr := f.getattr(a)
	if fserr == fs.OK {
		a.Size = uint64(len(f.plainData))
	}

	log.Debug("call file Getattr ", a)

	return fserr
}

func (f *loopbackFile) getattr(a *fuse.AttrOut) syscall.Errno {

	st := syscall.Stat_t{}
	err := syscall.Fstat(f.fd, &st)
	if err != nil {
		return fs.ToErrno(err)
	}
	a.FromStat(&st)

	return fs.OK
}

func (f *loopbackFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	log.Debug("call file Lseek")
	n, err := unix.Seek(f.fd, int64(off), int(whence))
	return uint64(n), fs.ToErrno(err)
}
