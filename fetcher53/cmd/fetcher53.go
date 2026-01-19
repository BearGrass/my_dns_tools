package main

import (
	"flag"
	"fmt"
	"log"

	"go.uber.org/zap"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/api"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/cache"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/config"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/iterator"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/logger"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/metrics"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/server"
)

const (
	DefaultCacheSize = 4096 * 1024
)

var (
	version   string
	buildtime string

	configFile   string
	showVersion  bool
	generateConf bool
)

func main() {
	flag.StringVar(&configFile, "conf", "fetch53.conf", "raftdns configure file")
	flag.BoolVar(&showVersion, "version", false, "display current version")
	flag.BoolVar(&generateConf, "genconf", false, "generate sample configure file")
	flag.Parse()

	if showVersion {
		fmt.Printf("fetch53 %s (build at %s)\n", version, buildtime)
		return
	}

	if generateConf {
		if err := config.GenerateDefaultConfig("fetch53.conf"); err != nil {
			log.Fatalf("generate default configure file failed:%s", err.Error())
		}
		return
	}

	conf, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("load configure failed:%s", err.Error())
	}

	logger.Init(conf.Log.Level)

	m := metrics.New()
	cacheSize := conf.Server.CacheCount
	if cacheSize <= 0 {
		cacheSize = DefaultCacheSize
	}
	cache := cache.NewCache(cacheSize)
	forwarder, err := iterator.NewForwardManager(&conf.Forward)
	if err != nil {
		logger.GetLogger().Fatal("load forward config failed", zap.Error(err))
	}

	iter, err := iterator.NewIterator(cache, forwarder, conf.Server.MaxOutgoingQueryCount)
	if err != nil {
		logger.GetLogger().Fatal("create itertator failed", zap.Error(err))
	}

	server, err := server.NewServer(conf.Server.Addrs, cache, iter, conf.Server.HandlerCount, m)
	if err != nil {
		logger.GetLogger().Fatal("create server failed", zap.Error(err))
	}

	server.Start()

	api.Run(conf.Server.CmdAddr, cache, m)
}
