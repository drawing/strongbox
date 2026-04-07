package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"

	config "strongbox/configuration"
	"strongbox/control"

	log "github.com/sirupsen/logrus"
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

func getDefaultConfigPath() string {
	usr, err := user.Current()
	if err != nil {
		log.Warn("Failed to get current user:", err)
		return "config.yml"
	}
	configDir := filepath.Join(usr.HomeDir, ".strongbox")
	err = os.MkdirAll(configDir, 0755)
	if err != nil {
		log.Warn("Failed to create config directory:", err)
		return "config.yml"
	}
	return filepath.Join(configDir, "config.yml")
}

func canRunUI() bool {
	switch runtime.GOOS {
	case "darwin":
		return os.Getenv("DISPLAY") != "" || os.Getenv("APP_NAME") != "" || os.Getenv("HOME") != ""
	case "linux":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	case "windows":
		return true
	default:
		return false
	}
}

func main() {
	defaultConfigPath := getDefaultConfigPath()
	
	runAsUI := flag.Bool("ui", canRunUI(), "run with ui.")
	configFile := flag.String("c", defaultConfigPath, "config file.")
	flag.Parse()

	err := config.Cfg.Load(*configFile)
	if err != nil {
		log.Fatal("read config file error:", err)
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		control.GetControl().Unmount()
	}()

	if *runAsUI {
		control.RunStrongBoxApp()
		return
	}

	passwd, err := credentials()
	if passwd == "" || err != nil {
		log.Fatal("must set password")
	}
	config.Cfg.SetPasswd(passwd)

	err = control.GetControl().Mount()
	if err != nil {
		log.Fatal("Mount failed:", err)
	}

	control.GetControl().Wait()
}
