package securefs

import (
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

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
	// r.content = []byte("")
}

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
