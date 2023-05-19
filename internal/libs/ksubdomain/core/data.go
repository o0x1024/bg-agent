package core

import (
	_ "bg-agent/internal/libs/ksubdomain/statik"
	"bufio"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rakyll/statik/fs"
)

func GetAsnData() []AsnStruct { //[]AsnStruct
	var asnData []AsnStruct = []AsnStruct{}
	statikFS, err := fs.New()
	if err != nil {
		log.Println(err.Error())
		return nil

	}
	r, err := statikFS.Open("/asn.txt")
	if err != nil {
		log.Println("打开资源文件失败:%s", err.Error())
		return nil

	}
	defer r.Close()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		err := scanner.Err()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			log.Println("错误:%s", line)
			return nil
		}
		asnid, _ := strconv.Atoi(parts[2])
		startIP := net.ParseIP(parts[0]).To4()
		endIP := net.ParseIP(parts[1]).To4()
		asnData = append(asnData, AsnStruct{
			ASN: asnid, Registry: parts[3], Cidr: Range2CIDR(startIP, endIP)})
	}
	return asnData
}
func getDefaultScripts() []string {
	var scripts []string
	StatikFS, err := fs.New()
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	fs.Walk(StatikFS, "/scripts", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Is this file not a script?
		if info.IsDir() || filepath.Ext(info.Name()) != ".lua" {
			return nil
		}
		// Get the script content
		data, err := fs.ReadFile(StatikFS, path)
		if err != nil {
			return err
		}
		scripts = append(scripts, string(data))
		return nil
	})

	return scripts
}
