package request

type PackagedData struct {
	Records
	AgentId      string   `json:"agent_id,,omitempty"`
	IntranetIpv4 []string `json:"IntranetIpv4"`
	IntranetIpv6 []string `json:"IntranetIpv6"`
	ExtranetIpv4 []string `json:"ExtranetIpv4"`
	ExtranetIpv6 []string `json:"ExtranetIpv6"`
	Hostname     string   `json:"host_name"`
	Version      string   `json:"version"`
	Product      string   `json:"product"`
}

type Records struct {
	ID string `json:"agentId"`

	KernelVersion   string `json:"kernel_version,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Platform        string `json:"platform,omitempty"`
	PlatformFamily  string `json:"platform_family,omitempty"`
	PlatformVersion string `json:"platform_version,omitempty"`
	TotalMem        string `json:"total_mem,omitempty"`

	Cpu        string `json:"cpu,omitempty"`
	Rss        string `json:"rss,omitempty"`
	ReadSpeed  string `json:"read_speed,omitempty"`
	WriteSpeed string `json:"write_speed,omitempty"`
	Pid        string `json:"pid,omitempty"`
	Nfd        string `json:"nfd,omitempty"`
	StartTime  string `json:"start_time,omitempty"`

	HostSerial string `json:"host_serial,omitempty"`
	HostId     string `json:"host_id,omitempty"`
	HostModel  string `json:"host_model,omitempty"`
	HostVendor string `json:"host_vendor,omitempty"`

	CpuName  string `json:"cpu_name,omitempty"`
	BootTime string `json:"boot_time,omitempty"`
	CpuUsage string `json:"cpu_usage,omitempty"`
	MemUsage string `json:"mem_usage,omitempty"`
}

// UploadReq
/* Type
数据类型，可选择：
1 - Agent心跳数据
2 - 攻击信息
3 - 异常信息
*/
type UploadReq struct {
	Type   int    `json:"type,omitempty"`
	Detail Detail `json:"detail,omitempty"`
}

type Detail struct {
	AgentId string `json:"agentId"`
	Pant
}

type Pant struct {
	Disk   string `json:"disk,omitempty"`
	Memory string `json:"memory,omitempty"`
	Cpu    string `json:"cpu,omitempty"`
}

type InputDataStruct struct {
	CompanyId int      `json:"companyId"`
	DataType  string   `json:"dataType"`
	Content   []string `json:"content"`
}
