package configuration

import (
	"crypto/sha1"
	"os"

	"gopkg.in/yaml.v3"

	log "github.com/sirupsen/logrus"
)

var Cfg Configuration

type Configuration struct {
	MountPoint string `yaml:"mountPoint,omitempty"`
	SecretPath string `yaml:"secretPath,omitempty"`

	AllowProcess []string `yaml:"allowProcess,omitempty"`

	SecretKey []byte
}

func (c *Configuration) Init(file string) error {
	yamlConfig, err := os.ReadFile(file)
	if err != nil {
		log.Fatal("yamlFile Open err:", err)
		return err
	}

	err = yaml.Unmarshal(yamlConfig, c)
	if err != nil {
		log.Fatal("Unmarshal:", err)
		return err
	}
	log.Debug(c)

	return nil
}

func (c *Configuration) SetPasswd(passwd string) {
	h := sha1.New()
	s := h.Sum([]byte(passwd))

	c.SecretKey = s[0:16]
}
