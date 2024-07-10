package cmd

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/memoio/meeda-node/core"
	"github.com/memoio/meeda-node/core/light"
	"github.com/memoio/meeda-node/database"
	"github.com/urfave/cli/v2"
	proof "github.com/memoio/go-did/file-proof"
)

var LightNodeCmd = &cli.Command{
	Name:  "light",
	Usage: "meeda light node",
	Subcommands: []*cli.Command{
		lightNodeRunCmd,
		// challengerNodeStopCmd,
		queryProfitsCmd,
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
		&cli.StringFlag{
			Name:  "chain",
			Usage: "input chain name, e.g.(dev)",
			Value: "product",
		},
		&cli.StringFlag{
			Name:  "ip",
			Usage: "input meeda store node's ip address",
			Value: "http://183.240.197.189:38082",
		},
		&cli.StringFlag{
			Name:  "pledge",
			Usage: "input pledge contract address",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "fileproof",
			Usage: "input fileproof contract address",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "proofcontrol",
			Usage: "input proofControl contract address",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "proofproxy",
			Usage: "input proofProxy contract address",
			Value: "",
		},
	},
	Action: func(ctx *cli.Context) error {
		endPoint := ctx.String("endpoint")
		sk := ctx.String("sk")
		chain := ctx.String("chain")
		ip := ctx.String("ip")

		pledge := ctx.String("pledge")
		fileproof := ctx.String("fileproof")
		proofControl := ctx.String("proofcontrol")
		proofProxy := ctx.String("proofproxy")

		privateKey, err := crypto.HexToECDSA(sk)
		if err != nil {
			privateKey, err = crypto.GenerateKey()
			if err != nil {
				return err
			}
		}

		addrs := &proof.ContractAddress{
			PledgeAddr: common.HexToAddress(pledge),
			ProofAddr: common.HexToAddress(fileproof),
			ProofControlAddr: common.HexToAddress(proofControl),
			ProofProxyAddr: common.HexToAddress(proofProxy),
		}

		cctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = light.InitLightNode(chain, privateKey, ip, addrs)
		if err != nil {
			return err
		}
		err = database.InitDatabase("~/.meeda-light")
		if err != nil {
			return err
		}

		dumper, err := core.NewDataAvailabilityDumper(chain, addrs)
		if err != nil {
			return err
		}

		err = dumper.DumpFileProof()
		if err != nil {
			return err
		}
		go dumper.SubscribeFileProof(cctx)

		prover, err := light.NewDataAvailabilityProver(chain, privateKey, addrs)
		if err != nil {
			log.Fatalf("new light node prover: %s\n", err)
		}
		err = prover.RegisterSubmitter()
		if err != nil {
			log.Fatalf("register submitter err: %s\n", err)
		}
		err = prover.Pledge()
		if err != nil {
			log.Fatalf("light node pledge err: %s\n", err)
		}
		go prover.ProveDataAccess(cctx)

		challenger, err := light.NewDataAvailabilityChallenger(chain, privateKey, addrs)
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

var queryProfitsCmd = &cli.Command{
	Name:  "profit",
	Usage: "query this node's profit of submitProof and challenge",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "address",
			Required: true,
			Usage:    "input this meeda light node's account address",
		},
	},
	Action: func(ctx *cli.Context) error {
		address := common.HexToAddress(ctx.String("address"))
		submitProfit := big.NewInt(0)
		challengeProfit := big.NewInt(0)
		challengePenalty := big.NewInt(0)

		err := database.InitDatabase("~/.meeda-light")
		if err != nil {
			return err
		}

		proofs, err := database.GetDAProofsBySubmitter(address)
		if err != nil {
			log.Fatal(err)
		}
		for _, proof := range proofs {
			submitProfit.Add(submitProfit, proof.Profit)
		}

		penalties, err := database.GetPenaltyByAccount(address, 0)
		if err != nil {
			log.Fatal(err)
		}
		for _, penalty := range penalties {
			amount := new(big.Int).Add(penalty.ToValue, penalty.FoundationValue)
			challengePenalty.Add(challengePenalty, amount)
		}

		rewards, err := database.GetPenaltyByAccount(address, 1)
		if err != nil {
			log.Fatal(err)
		}
		for _, reward := range rewards {
			challengeProfit.Add(challengeProfit, reward.ToValue)
		}

		fmt.Println("submitProfit:", submitProfit, "\nchallengeProfit:", challengeProfit, "\nchallengePenalty:", challengePenalty)
		return nil
	},
}

func NewLightServer(endpoint string) (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Meeda Light Node")
	})
	light.LoadLightModule(router.Group("/"))
	// Compatible with previous RPCs
	light.LoadLightModule(router.Group("/da"))

	return &http.Server{
		Addr:    endpoint,
		Handler: router,
	}, nil
}
