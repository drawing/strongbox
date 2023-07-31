package configuration

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"

	log "github.com/sirupsen/logrus"
)

var Cfg Configuration

type Configuration struct {
	MountPoint string `yaml:"mountPoint,omitempty"`
	SecretPath string `yaml:"secretPath,omitempty"`

	AllowProcess []string `yaml:"allowProcess,omitempty"`
}

func (c *Configuration) Init(file string) error {
	yamlConfig, err := ioutil.ReadFile(file)
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
