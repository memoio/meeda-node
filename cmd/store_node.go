package cmd

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/memoio/meeda-node/core"
	"github.com/memoio/meeda-node/core/store"
	"github.com/memoio/meeda-node/database"
	"github.com/urfave/cli/v2"
)

var StoreNodeCmd = &cli.Command{
	Name:  "store",
	Usage: "meeda store node",
	Subcommands: []*cli.Command{
		storeNodeRunCmd,
		// storeNodeStopCmd,
	},
}

var storeNodeRunCmd = &cli.Command{
	Name:  "run",
	Usage: "run meeda store node",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "endpoint",
			Aliases: []string{"e"},
			Usage:   "input your endpoint",
			Value:   ":8081",
		},
		&cli.StringFlag{
			Name:  "sk",
			Usage: "input your private key",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "chain",
			Usage: "input chain name, e.g.(dev)",
			Value: "product",
		},
		&cli.StringFlag{
			Name:  "ip",
			Usage: "input mefs user's ip",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "token",
			Usage: "input mefs user's token",
			Value: "",
		},
	},
	Action: func(ctx *cli.Context) error {
		endPoint := ctx.String("endpoint")
		sk := ctx.String("sk")
		chain := ctx.String("chain")
		ip := ctx.String("ip")
		token := ctx.String("token")

		privateKey, err := crypto.HexToECDSA(sk)
		if err != nil {
			privateKey, err = crypto.GenerateKey()
			if err != nil {
				return err
			}
		}

		cctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = store.InitStoreNode(chain, privateKey, ip, token)
		if err != nil {
			return err
		}
		err = database.InitDatabase("~/.meeda-store")
		if err != nil {
			return err
		}

		dumper, err := core.NewDataAvailabilityDumper(chain)
		if err != nil {
			return err
		}

		err = dumper.DumpFileProof()
		if err != nil {
			return err
		}
		go dumper.SubscribeFileProof(cctx)

		prover, err := store.NewDataAvailabilityProver(chain, privateKey)
		if err != nil {
			log.Fatalf("new store node prover: %s\n", err)
		}
		err = prover.Pledge()
		if err != nil {
			log.Fatalf("store node pledge err: %s\n", err)
		}
		go prover.ProveDataAccess(cctx)

		srv, err := NewStoreServer(endPoint)
		if err != nil {
			log.Fatalf("new store node server: %s\n", err)
		}

		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen: %s\n", err)
			}
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down server...")

		if err := srv.Shutdown(cctx); err != nil {
			log.Fatal("Server forced to shutdown: ", err)
		}

		log.Println("Server exiting")
		return nil
	},
}

func NewStoreServer(endpoint string) (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Meeda Store Node")
	})
	store.LoadStoreModule(router.Group("/"))

	return &http.Server{
		Addr:    endpoint,
		Handler: router,
	}, nil
}
