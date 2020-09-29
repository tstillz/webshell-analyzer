package common

import (
	"regexp"
)

type Config struct {
	Function_Generics []RegexDef
	Tags_Generics     []TagDef

	Function_Php []RegexDef
	Tags_Php     []TagDef

	Function_Asp []RegexDef
	Tags_Asp     []TagDef

	Function_Jsp []RegexDef
	Tags_Jsp     []TagDef

	Function_Cfm []RegexDef
	Tags_Cfm     []TagDef
}

type Base_Func func(bytesIn []byte, args ...interface{}) ([]byte, error) // for ones we define

type Action struct {
	Function  Base_Func
	Arguments interface{}
}

type RegexDef struct {
	Name              string
	Description       string
	Regex             regexp.Regexp
	DataCapture       regexp.Regexp
	PreDecodeActions  []Action
	PostDecodeActions []Action
	Functions         []Base_Func
}

type TagDef struct {
	Name        string
	Description string
	Regex       regexp.Regexp
	Attribute   bool
}

type OSInfo struct {
	Hostname    string   `json:"hostname"`
	EnvVars     []string `json:"envVars"`
	Username    string   `json:"username"`
	UserID      string   `json:"userID"`
	RealName    string   `json:"realName"`
	UserHomeDir string   `json:"userHomeDir"`
}

type FileObj struct {
	FilePath    string                    `json:"filePath"`
	Size        int64                     `json:"size"`
	Hashes      map[string]string         `json:"hashes"`
	Timestamps  FileTimes                 `json:"timestamps"`
	Matches     map[string]int            `json:"matches"`
	RawContents string                    `json:"rawContents,omitempty"`
	Decodes     map[string]int            `json:"decodes"`    // decoded regex and its contents for each
	Attributes  map[string]map[string]int `json:"attributes"` // Tags to define shell attributes
}

type Metrics struct {
	Scanned    int     `json:"scanned"`
	Matched    int     `json:"matches"`
	Clear      int     `json:"noMatches"`
	ScannedDir string  `json:"directory"`
	ScanTime   float64 `json:"scanDuration"`
	SystemInfo OSInfo  `json:"systemInfo"`
}

type FileTimes struct {
	Birth    string `json:"birth,omitempty"`
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
	Accessed string `json:"accessed,omitempty"`
}
