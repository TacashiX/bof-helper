# bof-helper

A small cli tool to make developing simple stack based buffer overflows with Immunity Debugger and Mona slightly more convenient.

### Installation

```powershell
go get -u github.com/tacashix/bof-helper
```

### Usage

```powershell
USAGE:
   bof-helper command [command options] [arguments...]

COMMANDS:
   set       saves ip, port, command and metasploit path to config file.
   fuzz      sends increasingly long buffer until server stops responding
   offset    sends metasploit generated pattern to detect offset
   badchars  sends payload to detect badchars
   generate  generates buffer overflow payload
   execute   executes generated payload
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
```