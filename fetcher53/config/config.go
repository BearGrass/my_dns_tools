package config

import (
	"os"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/configure"

	"gopkg.in/yaml.v2"
)

type Fetch53Conf struct {
	Server  ServerConf  `yaml:"server", required"true"`
	Forward ForwardConf `yaml:"forward" required:"true"`
	Log     LogConf     `yaml:"log" required:"true"`
}

type ServerConf struct {
	Addrs                 []string `yaml:"addrs" required:"true"`
	CmdAddr               string   `yaml:"cmd_addr" required:"true"`
	HandlerCount          int      `yaml:"handler_count" required:"true"`
	CacheCount            int      `yaml:"cache_count" required:"false"`
	MaxOutgoingQueryCount int      `yaml:"max_outgoing_query_count" required:"false"`
}

type ForwardConf struct {
	ForwardZones []ForwardZone `yaml:"zones" required:"true"`
}

type ForwardZone struct {
	Zone        string   `yaml:"zone" required:"true"`
	ServerAddrs []string `yaml:"server_addrs" required:"true"`
}

type LogConf struct {
	Level string `yaml:"level" required:"true"`
}

func LoadConfig(path string) (*Fetch53Conf, error) {
	var conf Fetch53Conf
	err := configure.Load(&conf, path)
	return &conf, err
}

func GenerateDefaultConfig(path string) error {
	conf := Fetch53Conf{
		Server: ServerConf{
			Addrs:                 []string{"127.0.0.1:53"},
			HandlerCount:          1024,
			MaxOutgoingQueryCount: 40960,
		},

		Forward: ForwardConf{
			ForwardZones: []ForwardZone{
				ForwardZone{"cn", []string{"114.114.114.114"}},
			},
		},

		Log: LogConf{
			Level: "debug",
		},
	}

	bs, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(bs)
	return err
}
