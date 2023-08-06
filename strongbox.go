package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	config "strongbox/configuration"
	"strongbox/securefs"
	"strongbox/ui"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	// "github.com/hanwen/go-fuse/v2/fuse/nodefs"

	nested "github.com/antonfisher/nested-logrus-formatter"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

func credentials() (string, error) {
	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	password := string(bytePassword)
	return strings.TrimSpace(password), nil
}

func main() {
	debug := flag.Bool("debug", false, "print debugging messages.")
	configFile := flag.String("config", "config.yml", "config file.")
	runAsUI := flag.Bool("ui", false, "run with ui.")
	flag.Parse()

	logger := &lumberjack.Logger{
		Filename:   "logs/box.log",
		MaxSize:    10, // MB
		MaxBackups: 3,
		MaxAge:     28,    //days
		Compress:   false, // disabled by default
	}
	// TODO:logger select
	if false {
		log.SetOutput(logger)
	}
	// log.SetLevel(log.DebugLevel)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&nested.Formatter{
		TimestampFormat: "2006-01-02 15:04:05",
		HideKeys:        true,
	})

	if *runAsUI {
		ui.RunStrongBoxApp()
		return
	}

	passwd, err := credentials()

	if passwd == "" {
		log.Fatal("must set password")
	}

	err = config.Cfg.Init(*configFile)
	if err != nil {
		log.Fatal("read config failed:", err)
	}
	config.Cfg.SetPasswd(passwd)

	err = securefs.GetDBInstance().InitDB()
	if err != nil {
		log.Fatal("init db failed:", err)
	}

	// TODO:mountPoint empty
	mountPoint := config.Cfg.MountPoint
	secretPath := config.Cfg.SecretPath

	loopbackRoot, err := securefs.NewRootBoxInode()
	if err != nil {
		log.Fatalf("NewRootBoxInode(%s): %v", secretPath, err)
	}

	sec := time.Second
	opts := &fs.Options{
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
		securefs.GetDBInstance().Close()
	}()

	server.Wait()
}
