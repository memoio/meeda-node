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
	"github.com/memoio/meeda-node/core/light"
	"github.com/urfave/cli/v2"
)

var LightNodeCmd = &cli.Command{
	Name:  "light",
	Usage: "meeda light node",
	Subcommands: []*cli.Command{
		lightNodeRunCmd,
		// challengerNodeStopCmd,
	},
}

var lightNodeRunCmd = &cli.Command{
	Name:  "run",
	Usage: "run meeda light node",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "endpoint",
			Aliases: []string{"e"},
			Usage:   "input your endpoint",
			Value:   ":8082",
		},
		&cli.StringFlag{
			Name:  "sk",
			Usage: "input your private key",
			Value: "",
		},
	},
	Action: func(ctx *cli.Context) error {
		endPoint := ctx.String("endpoint")
		sk := ctx.String("sk")

		privateKey, err := crypto.HexToECDSA(sk)
		if err != nil {
			privateKey, err = crypto.GenerateKey()
			if err != nil {
				return err
			}
		}

		cctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = light.InitLightNode(privateKey)
		if err != nil {
			return err
		}

		dumper, err := core.NewDataAvailabilityDumper("dev")
		if err != nil {
			return err
		}

		err = dumper.DumpFileProof()
		if err != nil {
			return err
		}
		go dumper.SubscribeFileProof(cctx)

		challenger, err := light.NewDataAvailabilityChallenger("dev", privateKey)
		if err != nil {
			return err
		}
		go challenger.ChallengeAggregatedCommits(cctx)

		srv, err := NewLightServer(endPoint)
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

func NewLightServer(endpoint string) (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Server")
	})
	light.LoadLightModule(router.Group("/"))

	return &http.Server{
		Addr:    endpoint,
		Handler: router,
	}, nil
}
