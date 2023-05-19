package response

type ResBase struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
}

type AgentRegisterRes struct {
	ResBase
	Data struct {
		Id            string `json:"id"`
		CoreAutoStart int    `json:"coreAutoStart,omitempty"`
	} `json:"data"`
}

type WkgRes struct {
	Code int    `json:"code"`
	Data string `json:"data"`
}

// taskid   1000 信息搜集针对域名和端口扫描    1001 漏洞扫描,漏洞扫描只针对website
type Task struct {
	TaskId   string    `json:"taskId,omitempty"`
	TaskNo   int       `json:"taskNo,omitempty"`
	Domains  []Domain  `json:"domains,omitempty"`
	IPs      []IP      `json:"IPs,omitempty"`
	WebSites []WebSite `json:"webSites,omitempty"`
}

type Domain struct {
	CId         int      `json:"cid,omitempty"`
	RootDomains []string `json:"rootDomains,omitempty"`
}

type IP struct {
	CId int      `json:"cid,omitempty"`
	Ips []string `json:"ips,omitempty"`
}

type WebSite struct {
	CId     int      `json:"cid,omitempty"`
	WebSite []string `json:"webSite,omitempty"`
}
