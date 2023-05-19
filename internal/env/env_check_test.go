package env

import (
	"bufio"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestEnvCheck(t *testing.T) {

	fmt.Println(runtime.GOOS)
	os := runtime.GOOS
	existRedis := false
	if os == "linux" {
		cmd := exec.Command("ps", "-ef")
		buf, err := cmd.Output()
		if err != nil {
			fmt.Println("[!] can not found [nuclei]. \n[*] please run [go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest] to install.")
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(string(buf)))
		for scanner.Scan() {
			content := scanner.Text()
			if strings.Contains(content, "redis") {
				existRedis = true
			}
		}
		if !existRedis {
			log.Println("[!] redis is not running or not install . please run after on install ")
			return
		}
	} else if os == "windows" {
		cmd := exec.Command("tasklist")
		buf, err := cmd.Output()
		if err != nil {
			fmt.Println("[!] can not found [nuclei]. \n[*] please run [go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest] to install.")
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(string(buf)))
		for scanner.Scan() {
			content := scanner.Text()
			if strings.Contains(content, "redis") {
				existRedis = true
			}
		}
		if !existRedis {
			log.Println("[!] redis is not running or not install . please run after on install ")
			return
		}
	}

	//cmd := exec.Command("nuclei" ,"-u","http://blog.sf-express.com:8080")
	//buf, err := cmd.Output()
	//if err != nil{
	//	fmt.Println("[!] can not found [nuclei]. \n[*] please run [go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest] to install.")
	//	os.Exit(0)
	//}
	//fmt.Println(string(buf))

	//cmd = exec.Command("subfinder" ,"-help")
	//_, err = cmd.Output()
	//if err != nil{
	//	fmt.Println("[!] can not found [nuclei]. \n[*] please run [go install -v bg-agent/internal/assetCollect/subfinder/cmd/subfinder@latest] to install.")
	//	os.Exit(0)
	//}

}
