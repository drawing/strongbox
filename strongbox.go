package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
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

func main() {
	runAsUI := flag.Bool("ui", false, "run with ui.")
	configFile := flag.String("c", "config.yml", "config file.")
	flag.Parse()

	err := config.Cfg.Load(*configFile)
	if err != nil {
		log.Fatal("read config file error:", err)
	}

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

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		control.GetControl().Unmount()
	}()

	control.GetControl().Wait()
}
