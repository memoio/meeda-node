package main

import (
	"fmt"
	"os"

	"github.com/memoio/meeda-node/cmd"
	"github.com/urfave/cli/v2"
)

func main() {
	local := make([]*cli.Command, 0, 1)
	local = append(local, cmd.StoreNodeCmd, cmd.LightNodeCmd, cmd.VersionCmd)
	app := cli.App{
		Commands: local,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "version",
				Aliases: []string{"v"},
				Usage:   "Show application version",
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.Bool("version") {
				fmt.Println(cmd.Version + "+" + cmd.BuildFlag)
			}
			return nil
		},
	}
	app.Setup()

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n\n", err) // nolint:errcheck
		os.Exit(1)
	}
}
