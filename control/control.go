package control

import (
	"errors"
	"time"

	config "strongbox/configuration"
	"strongbox/securefs"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	log "github.com/sirupsen/logrus"
)

type Control struct {
	server  *fuse.Server
	running bool
}

var controlInstance *Control

func GetControl() *Control {
	if controlInstance == nil {
		controlInstance = &Control{}
	}
	return controlInstance
}

func (c *Control) Mount() error {
	if c.running {
		return errors.New("already mounted")
	}

	err := securefs.GetDBInstance().InitDB()
	if err != nil {
		log.Error("init db failed:", err)
		return err
	}

	mountPoint := config.Cfg.MountPoint
	if len(mountPoint) == 0 {
		return errors.New("mount point must set")
	}

	boxfsRoot, err := securefs.NewRootBoxInode()
	if err != nil {
		log.Errorf("NewRootBoxInode: %v", err)
		return err
	}

	sec := time.Second
	opts := &fs.Options{
		AttrTimeout:  &sec,
		EntryTimeout: &sec,

		NullPermissions: true, // Leave file permissions on "000" files as-is

		MountOptions: fuse.MountOptions{
			// Debug: *debug,
			Name: "strongbox",
		},
	}

	c.server, err = fs.Mount(mountPoint, boxfsRoot, opts)
	if err != nil {
		log.Errorf("Mount fail: %v\n", err)
		return err
	}
	log.Info("Mounted: ", mountPoint)

	c.running = true
	return nil
}

func (c *Control) Wait() {
	c.server.Wait()
	log.Info("Wait Finish")
}

func (c *Control) Running() bool {
	return c.running
}

func (c *Control) Unmount() {
	if !c.running {
		return
	}
	log.Info("Unmount: ", config.Cfg.MountPoint)
	c.server.Unmount()
	securefs.GetDBInstance().Close()
	c.running = false
}
