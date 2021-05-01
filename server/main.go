// Copyright (c) 2019 IoTeX Foundation
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

// Usage:
//   make build
//   ./bin/server -config-file=./config.yaml
//

package main

import (
	"context"
	"flag"
	"fmt"
	glog "log"
	"os"
	"os/signal"
	"syscall"

	"github.com/iotexproject/go-pkgs/hash"
	"go.uber.org/zap"

	"github.com/iotexproject/iotex-core/blockchain/block"
	"github.com/iotexproject/iotex-core/blockchain/genesis"
	"github.com/iotexproject/iotex-core/config"
	"github.com/iotexproject/iotex-core/pkg/log"
	"github.com/iotexproject/iotex-core/server/itx"
)

func init() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr,
			"usage: server -config-path=[string]\n")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	genesisCfg, err := genesis.New()
	if err != nil {
		glog.Fatalln("Failed to new genesis config.", zap.Error(err))
	}

	cfg, err := config.New()
	if err != nil {
		glog.Fatalln("Failed to new config.", zap.Error(err))
	}
	if err = initLogger(cfg); err != nil {
		glog.Fatalln("Cannot config global logger, use default one: ", zap.Error(err))
	}

	if config.EVMNetworkID() == 0 {
		glog.Fatalln("EVM Network ID is not set, call config.New() first")
	}
	if config.GenesisTimestamp() == 0 {
		glog.Fatalln("Genesis timestamp is not set, call config.New() first")
	}
	block.LoadGenesisHash()
	if block.GenesisHash() == hash.ZeroHash256 {
		glog.Fatalln("Genesis hash is not set, call block.LoadGenesisHash() first")
	}

	cfg.Genesis = genesisCfg
	cfgToLog := cfg
	cfgToLog.Chain.ProducerPrivKey = ""
	log.S().Infof("Config in use: %+v", cfgToLog)
	log.S().Infof("EVM Network ID: %d", config.EVMNetworkID())
	log.S().Infof("Genesis hash: %x", block.GenesisHash())

	// start server
	svr, err := itx.NewServer(cfg)
	if err != nil {
		glog.Fatalln("Failed to create local server.", zap.Error(err))
	}
	if err = svr.Start(ctx); err != nil {
		glog.Fatalln("Failed to start local server.", zap.Error(err))
	}

	// handle shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	signal.Notify(stop, syscall.SIGKILL, syscall.SIGTERM)
	select {
	case <-stop:
		log.L().Info("shutting down ...")
	case <-ctx.Done():
		log.L().Info("context cancelled ...")
	}
	if err = svr.Stop(ctx); err != nil {
		glog.Fatalln("Failed to stop local server.", zap.Error(err))
	}
}

func initLogger(cfg config.Config) error {
	addr := cfg.ProducerAddress()
	return log.InitLoggers(cfg.Log, cfg.SubLogs, zap.Fields(
		zap.String("ioAddr", addr.String()),
	))
}
