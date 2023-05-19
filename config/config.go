package config

import (
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

var Cfg *Config = new(Config)

type Config struct {
	Server_host string `yaml:"server_host"`
	Server_port int    `yaml:"server_port"`
	WkgUrl      string `yaml:"wkg_url"`
	V3Token     string `yaml:"v3token"`
	Wechat      string `yaml:"webchat"`
}

func LoadConfig(configFile string) (config *Config, err error) {
	f, err := os.Open(configFile)
	if err != nil {
		return
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	config = new(Config)
	err = yaml.Unmarshal(data, config)
	//fmt.Println("load config, time:", time.Now().Format("2006-01-02 15:04:05"), "info:", config, "error:", err)
	return
}
