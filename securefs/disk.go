package securefs

import (
	"log"
	"os"

	diskfs "github.com/diskfs/go-diskfs"
	disk "github.com/diskfs/go-diskfs/disk"
	filesystem "github.com/diskfs/go-diskfs/filesystem"
)

func InitFat32Filesystem(imagePath string) (filesystem.FileSystem, error) {
	var local_disk *disk.Disk = nil
	var local_fs filesystem.FileSystem = nil

	_, err := os.Stat(imagePath)
	if os.IsNotExist(err) {
		var size int64 = 10 * 1024 * 1024 // 10 MB

		// create a disk image
		local_disk, err = diskfs.Create(imagePath, size, diskfs.Raw, diskfs.SectorSizeDefault)
		if err != nil {
			log.Fatal("Create Disk error: ", err)
			return nil, err
		}

		local_fs, err = local_disk.CreateFilesystem(disk.FilesystemSpec{Partition: 0, FSType: filesystem.TypeFat32})
		if err != nil {
			log.Fatal("Create Filesystem error: ", err)
			return local_fs, err
		}
	} else {
		local_disk, err = diskfs.Open(imagePath)
		if err != nil {
			log.Fatal("Open Disk error: ", err)
			return nil, err
		}
		local_fs, err = local_disk.GetFilesystem(0)
		if err != nil {
			log.Fatal("Open Filesystem error: ", err)
			return local_fs, err
		}
	}

	return local_fs, nil
}
