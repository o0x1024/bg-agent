package assetCollect

import (
	"bg-agent/global"
	"bg-agent/internal/db"
	"bg-agent/internal/notice/request"
	utils2 "bg-agent/internal/utils"
	"bufio"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	tr     = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client = http.Client{Timeout: 2 * time.Second, Transport: tr}
	req    = &http.Request{}
)

func aliveDetectByHttpx() {
	//var err error
	//
	//log.Println("[*] alive detect.")
	//
	//cmd := exec.Command("httpx", "-l", global.NewDomainPath, "-silent", "-o", global.NewAlivePath)
	//_, err = cmd.Output()
	//if err != nil {
	//	log.Println("[!] httpx err[", err, "]")
	//	global.Alarm <- utils2.GenReportInfo(err)
	//}
	//err = cmd.Wait()
	//if err != nil {
	//	global.Alarm <- utils2.GenReportInfo(err)
	//}
	//log.Println("[*] alive done.")
}

func getRootDomainFromWkg() (rootDomain []string) {
	var res *http.Response
	var err error
	for {
		res, err = http.Get(global.WkgURL + "/v2/getRootDomain")
		if err != nil {
			log.Println("[!] can not get root domain from server.")
			global.Alarm <- utils2.GenReportInfo(err)
			continue
		} else {
			break
		}
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println("[!] getRootDomain error.[", err, "]")
		global.Alarm <- utils2.GenReportInfo(err)
		return
	}
	rt := request.RespType{}
	err = json.Unmarshal(body, &rt)
	if err != nil {
		log.Println("[!] getRootDomain json error.[", err, "]")
		global.Alarm <- utils2.GenReportInfo(err)
		return
	}
	rootDomain = rt.Data

	return

}

func CollentResultAndSaveToFile(tars []string) {
	var err error
	var f *os.File
	fileName := global.NewDomainPath
	if utils2.CheckFileIsExist(fileName) { //如果文件存在
		f, err = os.OpenFile(fileName, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0666) //打开文件
	} else {
		f, err = os.Create(fileName) //创建文件
	}
	if err != nil {
		log.Println(err)
		global.Alarm <- utils2.GenReportInfo(err)
		os.Exit(0)
	}
	w := bufio.NewWriter(f)
	//接受收集到的域名信息并写入文件
	for _, v := range tars {
		ex := db.Exists(v)
		if ex {
			continue
		} else {
			err = db.Set(v, v)
			if err != nil {
				global.Alarm <- utils2.GenReportInfo(err)
				continue
			}
			w.WriteString(v + "\n")
		}
	}
	w.Flush()
	f.Close()
}

func getFofaRuleFromWkg() (fofaRule []string) {
	var res *http.Response
	var err error
	for {
		res, err = http.Get(global.WkgURL + "/v2/getFofaRule")
		if err != nil {
			log.Println("[!] can not get root fofa rule from server.")
			global.Alarm <- utils2.GenReportInfo(err)
			return
		} else {
			break
		}
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println("[!] getFofaRule error.[", err, "]")
		global.Alarm <- utils2.GenReportInfo(err)
		return
	}
	rt := request.RespType{}
	err = json.Unmarshal(body, &rt)
	if err != nil {
		log.Println("[!] getFofaRule json error.[", err, "]")
		global.Alarm <- utils2.GenReportInfo(err)
		return
	}
	fofaRule = rt.Data

	return
}

// //收集到的域名信息需要探活，加上http|https前缀
func work(target string) {
	//if strings.Contains(target,"http"){
	//	global.AllAsset = append(global.AllAsset,target)
	//}else{
	//	httpsUrl := "https://"+target
	//	httpUrl := "http://"+target
	//
	//	req ,_  = http.NewRequest("GET",httpsUrl,nil)
	//	req.Header.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.55")
	//
	//	_ ,err := client.Do(req)
	//	if err == nil{
	//		global.AllAsset = append(global.AllAsset,httpsUrl)
	//	}else{
	//		req.URL ,_= url.Parse(httpUrl)
	//		_ ,err = client.Do(req)
	//		if err == nil{
	//			global.AllAsset = append(global.AllAsset,httpUrl)
	//		}
	//
	//		//global.Host <- httpsUrl
	//	}
	//}
}

func SaveNewDoaminToFile() {
	//var err error
	//var f *os.File
	//fileName := global.NewDomainPath
	//
	//log.Println("[*] new assets write to file.")
	//if utils.CheckFileIsExist(fileName) { //如果文件存在
	//	f, err = os.OpenFile(fileName, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0666) //打开文件
	//} else {
	//	f, err = os.Create(fileName) //创建文件
	//}
	//if err != nil{
	//	log.Println(err)
	//	global.Alarm <- utils.GenReportInfo(err)
	//	return
	//}
	//w := bufio.NewWriter(f)
	//for _,v:=range global.AllAsset {
	//	//判断redis缓存中是否有了，有了就下一个，没有就存入缓存，并写入文件
	//	ok := db.Exists(v)
	//	if ok{
	//		continue
	//	}else{
	//		err = db.Set(v,v)
	//		if err != nil {
	//			global.Alarm <- utils.GenReportInfo(err)
	//			continue
	//		}
	//		//缓存中没有的，写入文件加入待扫描列表
	//		_, err := w.WriteString(v+"\n")
	//		if err != nil{
	//			global.Alarm <- utils.GenReportInfo(err)
	//			log.Println(err)
	//			return
	//		}
	//	}
	//}
	//w.Flush()
	//f.Close()
}
