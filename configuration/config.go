package configuration

import (
	"crypto/sha1"
	"os"

	"gopkg.in/yaml.v3"

	nested "github.com/antonfisher/nested-logrus-formatter"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Cfg Configuration

type LoggerConfig struct {
	Filename string `yaml:"filename,omitempty"`
	// [debug, info, warn, error]
	Level string `yaml:"level,omitempty"`
}

type PermissionConfig struct {
	// action [pass, deny]
	DefaultAction string `yaml:"defaultAction,omitempty"`
	// whitelist processes
	AllowProcess []string `yaml:"allowProcess,omitempty"`
	// blacklist processes
	DenyProcess []string `yaml:"denyProcess,omitempty"`
}

type BackupConfig struct {
	Path   string `yaml:"path,omitempty"`
	Memory bool   `yaml:"memory,omitempty"`
}

type Configuration struct {
	ConfigFile string

	MountPoint string `yaml:"mountPoint,omitempty"`

	Permission PermissionConfig `yaml:"permission,omitempty"`
	Logger     LoggerConfig     `yaml:"logger,omitempty"`
	Backup     BackupConfig     `yaml:"backup,omitempty"`

	SecretKey []byte
}

func (c *Configuration) initLogger() {
	if len(c.Logger.Filename) > 0 {
		logger := &lumberjack.Logger{
			Filename:   c.Logger.Filename,
			MaxSize:    10, // MB
			MaxBackups: 3,
			MaxAge:     28,    //days
			Compress:   false, // disabled by default
		}
		log.SetOutput(logger)
	}

	level := log.InfoLevel
	switch c.Logger.Level {
	case "debug":
		level = log.DebugLevel
	case "warn":
		level = log.WarnLevel
	case "error":
		level = log.ErrorLevel
	}
	log.SetLevel(level)
	log.SetFormatter(&nested.Formatter{
		TimestampFormat: "2006-01-02 15:04:05",
		HideKeys:        true,
	})
}

func (c *Configuration) Load(file string) error {
	yamlConfig, err := os.ReadFile(file)
	if err != nil {
		log.Error("yamlFile Open err:", err)
		return err
	}

	// backup default value
	c.Backup.Memory = true
	c.Backup.Path = ""
	c.ConfigFile = file

	err = yaml.Unmarshal(yamlConfig, c)
	if err != nil {
		log.Error("unmarshal:", err)
		return err
	}

	c.initLogger()

	log.Info("Init Config:", c)
	return nil
}

func (c *Configuration) Save() error {

	out, err := yaml.Marshal(c)
	if err != nil {
		log.Error("marshal config:", err)
		return err
	}

	err = os.WriteFile(c.ConfigFile, out, 0777)
	if err != nil {
		log.Error("write config:", err)
		return err
	}

	return nil
}

func (c *Configuration) SetPasswd(passwd string) {
	h := sha1.New()
	s := h.Sum([]byte(passwd))

	c.SecretKey = s[0:16]
}
