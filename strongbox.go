package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"strongbox/securefs"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	// "github.com/hanwen/go-fuse/v2/fuse/nodefs"

	nested "github.com/antonfisher/nested-logrus-formatter"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	config "strongbox/configuration"
)

func main() {
	debug := flag.Bool("debug", false, "print debugging messages.")
	flag.Parse()

	err := config.Cfg.Init("config.yml")
	if err != nil {
		log.Fatal("read config failed:", err)
		return
	}

	logger := &lumberjack.Logger{
		Filename:   "logs/box.log",
		MaxSize:    10, // MB
		MaxBackups: 3,
		MaxAge:     28,    //days
		Compress:   false, // disabled by default
	}
	// TODO logger select
	if false {
		log.SetOutput(logger)
	}
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&nested.Formatter{
		TimestampFormat: "2006-01-02 15:04:05",
		HideKeys:        true,
	})

	// TODO mountPoint empty
	mountPoint := config.Cfg.MountPoint
	secretPath := config.Cfg.SecretPath

	/*
		root := securefs.NewSecureNodeFSRoot(secretPath)
		conn := nodefs.NewFileSystemConnector(root, nil)
		server, err := fuse.NewServer(conn.RawFS(), mountPoint, &fuse.MountOptions{
			Debug: *debug,
		})
		if err != nil {
			log.Error("Mount fail: ", err)
			os.Exit(1)
		}
		log.Print("Mounted: ", mountPoint)

		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			select {
			case sig := <-c:
				{
					log.Infof("Got %s signal. Unmount...", sig)
					server.Unmount()
				}
			}
		}()

		server.Serve()
	*/
	loopbackRoot, err := securefs.NewSecureLoopbackRoot(secretPath)
	if err != nil {
		log.Fatalf("NewLoopbackRoot(%s): %v", secretPath, err)
	}

	sec := time.Second
	opts := &fs.Options{
		// The timeout options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		AttrTimeout:  &sec,
		EntryTimeout: &sec,

		NullPermissions: true, // Leave file permissions on "000" files as-is

		MountOptions: fuse.MountOptions{
			Debug: *debug,
			// Name:              "loopback",
		},
	}

	server, err := fs.Mount(mountPoint, loopbackRoot, opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	log.Info("Mounted: ", mountPoint)

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Info("Unmount: ", mountPoint)
		server.Unmount()
	}()

	server.Wait()
}
