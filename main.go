package main

import (
	cm "./common"
	ft "./timestamps"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

func Scan_worker(wg *sync.WaitGroup, rawContents bool) {
	for j := range cm.FilesToScan {
		Jdata := cm.FileObj{}
		Jdata.FilePath = j
		fileMatches, decodes, size, tags := cm.ProcessFile(j)
		Jdata.Attributes = tags
		Jdata.Decodes = decodes
		Jdata.Size = size
		Jdata.Matches = fileMatches

		md5Hash, err := cm.Md5HashFile(j)
		if err != nil {
			log.Println(err)
		}

		sha1Hash, err := cm.SHA1HashFile(j)
		if err != nil {
			log.Println(err)
		}

		sha256Hash, err := cm.SHA256HashFile(j)
		if err != nil {
			log.Println(err)
		}

		Jdata.Hashes = map[string]string{}
		Jdata.Hashes["md5"] = md5Hash
		Jdata.Hashes["sha1"] = sha1Hash
		Jdata.Hashes["sha256"] = sha256Hash

		// File Timestamps
		timestamps, err := ft.StatTimes(j)
		Jdata.Timestamps = timestamps

		if len(fileMatches) != 0 {
			cm.Matched = cm.Matched + 1

		} else if len(fileMatches) == 0 {
			if cm.VerboseMode == true {
				data, err := json.MarshalIndent(Jdata, "", " ")
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%s\n", string(data))
			}
			cm.Cleared = cm.Cleared + 1
			continue
		}

		if rawContents {
			Jdata.RawContents = cm.CompressEncode(j, Jdata.Size)
		}

		// PROD
		data, err := json.Marshal(Jdata)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", data)
	}
	wg.Done()
}

func init() {

	// TODO: Remove matches item and stick it all under behaviors as nested map[string]map[string]int{} so we can see what the behavior mapped too.

	//// Generics
	cm.GlobalMap.Function_Generics = []cm.RegexDef{{
		Name:        "Generic_URL_Decode",
		Regex:       *regexp.MustCompile(`(?i)(https?(?:%3A%2F%2F|://%).+(?:\s+|'|"|=|\?))`),
		DataCapture: *regexp.MustCompile(`(?i)(https?(?:%3A%2F%2F|://%).+(?:\s+|'|"|=|\?))`),
		PreDecodeActions: []cm.Action{
			{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
			{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
		},
		Functions: []cm.Base_Func{cm.UrlDecode},
	},
		{
			Name:        "Generic_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]{8,}(?:'|"))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]{8,}(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		},
		{
			Name:        "Generic_Multiline_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:'|')(?:[A-Za-z0-9+\/=]{4,})+(?:'|")\.?(?:\r|\n)?)+`),
			DataCapture: *regexp.MustCompile(`(?i)(?:(?:'|')(?:[A-Za-z0-9+\/=]{4,})+(?:'|")\.?(?:\r|\n)?)+`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\r\n", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\n", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\r", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{".", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		},
	}
	cm.GlobalMap.Tags_Generics = []cm.TagDef{
		{
			Name:        "Generic_Execution",
			Description: "Looks for execution associated with web shells",
			Regex:       *regexp.MustCompile(`(?i)(?:\w+\.run\("%comspec% /c)`),
		},
		{
			Name:        "Generic_Webshell_Keywords",
			Description: "Looks for common keywords associated with web shells",
			Regex:       *regexp.MustCompile(`(?i)(?:xp_cmdshell|Database\s+Dump|ShiSanObjstr|Net\s+Sploit|SQLI\+Scan|shell\s?code|envlpass|files?man|c0derz\s?shell|md5\s?cracker|umer\s?rock|asp\s?cmd\s?shell|JspSpy|uZE\s?Shell|AK-74\s?Security\s?Team\s?Web\s?Shell|WinX\s?Shell|PHP C0nsole|cfmshell|cmdshell|Gamma\s?Web\s?Shell|ASPXSpy|IISSpy|Webshell|ASPX?\s?Shell|STNC WebShell|GRP\s?WebShell|National Cracker Crew)`),
		},
		{
			Name:        "Generic_IP/DomainName",
			Description: "Looks for IP addresses or domain names",
			Regex:       *regexp.MustCompile(`(?i)(https?://(?:\d+\.\d+\.\d+\.\d+|\w+(?:\.\w+\.\w+|\.\w+)?)[/\w+\?=\.]+)`),
			Attribute:   true,
		},
		{
			Name:        "Generic_Embedded_Executable",
			Description: "Looks for magic bytes associated with a PE file",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:0x)?4D5A)`),
		},
		{
			Name:        "Generic_Windows_Reconnaissance",
			Description: "Looks for commands associated with reconnaissance",
			Regex:       *regexp.MustCompile(`(?i)(?:tasklist|netstat|ipconfig|whoami|net\s+(?:localgroup|user)(?:\s|\w)+/add|net\s+start\s+)`),
		},
		{
			Name:        "Generic_Windows_Commands",
			Description: "Looks for calls to commonly used windows binaries",
			Regex:       *regexp.MustCompile(`(?i)(?:[wc]script\.(?:shell|network)|(?:cmd|powershell|[wc]script)(?:\.exe)?|cmd\.exe\s+/c)`),
		},
		{
			Name:        "Generic_Windows_Registry_Persistence",
			Description: "Looks for registry paths associated with Windows persistence mechanisms",
			Regex:       *regexp.MustCompile(`(?i)(?:\\currentversion\\(?:run|runonce))`),
		},
		{
			Name:        "Generic_Defense_Evasion",
			Description: "Looks for registry paths associated with Windows persistence mechanisms",
			Regex:       *regexp.MustCompile(`(?i)(?:strpos\(\$_SERVER\['HTTP_USER_AGENT'\],'Google'\))`),
		},
		{
			Name:        "Generic_Embedding_Code_C",
			Description: "Looks for C code constructs within a file associated to a web shell",
			Regex:       *regexp.MustCompile(`(?i)(?:include\s<sys/socket\.h>|socket\(AF_INET,SOCK_STREAM|bind\(|listen\(|daemon\(1,0\))`),
			Attribute:   true,
		},
		{
			Name:        "Generic_Embedding_Code_Perl",
			Description: "Looks for Perl code constructs within a file associated to a web shell",
			Regex:       *regexp.MustCompile(`(?i)(?:getprotobyname\('tcp'\)|#!/usr/bin/perl)|exec\s+\{'/bin/sh'\}\s+'-bash'`),
			Attribute:   true,
		},
		{
			Name:        "Generic_Embedding_Code_Python",
			Description: "Looks for Python code constructs within a file associated to a web shell",
			Regex:       *regexp.MustCompile(`(?i)(?:)#!/usr/bin/python|cgitb\.enable\(\)|print_exc\(|import\ssubprocess|subprocess\.Popen\(|urllib\.urlretrieve\(`),
			Attribute:   true,
		},
	}

	//// PHP
	cm.GlobalMap.Function_Php = []cm.RegexDef{
		{
			Name:        "PHP_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(?:=|\s+)(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		},
		{
			Name:        "PHP_GzInflate_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(gzinflate\(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))\)`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64, cm.GZInflate},
		},
		{
			Name:        "PHP_Url_Decode",
			Regex:       *regexp.MustCompile(`(?i)(urldecode\('?"?[%\w+]+'?"?\))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")'?"?[%\w+]+'?"?)`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.UrlDecode},
		},
		{
			Name:        "PHP_Dot_Concatenation",
			Regex:       *regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			DataCapture: *regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"'.'", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\".\"", "", -1}},
			},
			Functions: []cm.Base_Func{},
		}, {
			Name:        "PHP_CharCode",
			Regex:       *regexp.MustCompile(`(?:(?:\.chr\(\d+\))+|array\((?:\r|\n|\r\n|\n\r|\s+)chr\(\d+\)\.(chr\(\d+\)(?:\.|,)(?:\s+)?)+chr\(\d+\))`),
			DataCapture: *regexp.MustCompile(`(?:(?:\.chr\(\d+\))+|chr\(\d+\)\.(chr\(\d+\)(?:\.|,)(?:\s+)?)+chr\(\d+\))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"chr", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{" ", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{")", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"(", "|", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{",", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{".", "", -1}},
			},
			Functions: []cm.Base_Func{cm.CharDecode}, // looks for strings Split by pipe
		}}
	cm.GlobalMap.Tags_Php = []cm.TagDef{
		{
			Name:        "PHP_Banned_Function",
			Description: "Banned PHP functions are commonly disabled by hosting providers due to security concerns",
			Regex:       *regexp.MustCompile(`(?i)(?:allow_url_fopen\(|fsockopen\(|getrusage\(|get_current_user\(|set_time_limit\(|getmyuid\(|getmypid\(|dl\(|leak\(|listen\(|chown\(|chgrp\(|realpath\(|link\(|exec\(|passthru\(|curl_init\()`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Reconnaissance",
			Description: "Looks for common PHP functions used for gaining further insight into the environment.",
			Regex:       *regexp.MustCompile(`(?i)(?:@ini_get\("disable_functions"\)|gethostbyname\(|phpversion\(|disk_total_space\(|posix_getpwuid\(|posix_getgrgid\(|phpinfo\()`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Database_Operations",
			Description: "Looks for common PHP functions used for interacting with a database.",
			Regex:       *regexp.MustCompile(`(?i)(?:'mssql_connect\('|ocilogon\(|mysql_list_dbs\(mysql_num_rows\(|mysql_dbname\(|mysql_create_db\(|mysql_drop_db\(|mysql_query\(|mysql_exec\()`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Disk_Operations",
			Description: "Looks for common PHP functions used for interacting with a file system.",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:\s|@)rename\(|(%s|@)chmod\(|(%s|@)fileowner\(|(%s|@)filegroup\(|fopen\(|fwrite\(\))`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Execution",
			Description: "Looks for common PHP functions used for executing code.",
			Regex:       *regexp.MustCompile(`(?i)(?:(?:\s|\()(?:curl_exec\(|eval\(|exec\(|shell_exec\(|execute\(|passthru\()|(?:assert|array)\(\$_REQUEST\['?"?\w+"?'?\]|\$\{"?'?_REQUEST'?"?\})`),
		},
		{
			Name:        "PHP_Defense_Evasion",
			Description: "Looks for common PHP functions used for hiding or obfuscating code.",
			Regex:       *regexp.MustCompile(`(?i)(?:gzinflate\(base64_decode\(|preg_replace\(|\(md5\(md5\(\$\w+\))`),
			Attribute:   true,
		},
		{
			Name:        "PHP_Network_Operations",
			Description: "Looks for common PHP functions used for network operations such as call backs",
			Regex:       *regexp.MustCompile(`(?i)(?:fsockopen\()`),
		},
	}

	//// ASP/X
	cm.GlobalMap.Function_Asp = []cm.RegexDef{
		{
			Name:        "ASP_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(?:=|\s+)(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64},
		}, {
			Name:        "ASP_GzInflate_Base64Decode",
			Regex:       *regexp.MustCompile(`(?i)(gzinflate\(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))\)`),
			DataCapture: *regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []cm.Base_Func{cm.DecodeBase64, cm.GZInflate},
		}, {
			Name:        "ASP_Comment_Obfuscation1",
			Regex:       *regexp.MustCompile(`(?i).*(?:"|')\&(?:"|')\w+(?:"|')`),
			DataCapture: *regexp.MustCompile(`(?i).*(?:"|')\&(?:"|')\w+(?:"|')`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplace, Arguments: []interface{}{"\"&\"", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"'&'", "", -1}},
			},
			Functions: []cm.Base_Func{},
		}, {
			Name:        "ASP_Comment_Obfuscation2",
			Regex:       *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			DataCapture: *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplaceRegex, Arguments: []interface{}{`(?i)(?:"|')\+\w+\+(?:"|')`, "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"+", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\"++\"", "", -1}},
			},
			Functions: []cm.Base_Func{},
		}, { // TODO: Handle vbscript.encode and jsp encoding
			Name:        "ASP_VBScriptEncode",
			Regex:       *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			DataCapture: *regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			PreDecodeActions: []cm.Action{
				{Function: cm.StringReplaceRegex, Arguments: []interface{}{`(?i)(?:"|')\+\w+\+(?:"|')`, "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"+", "", -1}},
				{Function: cm.StringReplace, Arguments: []interface{}{"\"++\"", "", -1}},
			},
			Functions: []cm.Base_Func{},
		},
	}
	cm.GlobalMap.Tags_Asp = []cm.TagDef{
		{
			Name:        "ASP_Execution",
			Description: "ASP functions associated with code execution",
			Regex:       *regexp.MustCompile(`(?i)(?:e["+/*-]+v["+/*-]+a["+/*-]+l["+/*-]+\(|system\.diagnostics\.processstartinfo\(\w+\.substring\(|startinfo\.filename=\"?'?cmd\.exe"?'?|\seval\(request\.item\["?'?\w+"?'?\](?:,"?'?unsafe"?'?)?|execute(?:\(|\s+request\(\"\w+\"\))|RunCMD\(|\seval\(|COM\('?"?WScript\.(?:shell|network)"?'?|response\.write\()`),
		},
		{
			Name:        "Database_Command_Execution",
			Description: "ASP functions associated with code execution using database commands",
			Regex:       *regexp.MustCompile(`(?i)\w+\.(?:ExecuteNonQuery|CreateCommand)\(`),
		},
		{
			Name:        "ASP_Disk_Operations",
			Description: "ASP functions associated with disk operations",
			Regex:       *regexp.MustCompile(`(?i)(?:createtextfile\(|server\.createobject\(\"Scripting\.FileSystemObject\"\))`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Suspicious",
			Description: "ASP code blocks that are suspicious",
			Regex:       *regexp.MustCompile(`(?i)(?:deletefile\(server\.mappath\(\"\w+\.\w+\"\)\)|language\s+=\s+vbscript\.encode\s+%>(?:\s*|\r|\n)<%\s+response\.buffer=true:server\.scripttimeout=|(?i)language\s+=\s+vbscript\.encode%><%\n?\r?server\.scripttimeout=|executeglobal\(|server\.createobject\(\w+\(\w{1,5},\w{1,5}\)\))`),
		},
		{
			Name:        "ASP_Targeted_Object_Creation",
			Description: "ASP object creations commonly leveraged in webshells",
			Regex:       *regexp.MustCompile(`(?i)server\.createobject\(\"(?:msxml2\.xmlhttp|microsoft\.xmlhttp|WSCRIPT\.SHELL|ADODB\.Connection)\"\)`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Suspicious_imports",
			Description: "Looks for imported dependencies that are common with WebShells",
			Regex:       *regexp.MustCompile(`(?i)name(?:space)?="(?:system\.(?:serviceprocess|threading|(?:net\.sockets)))"?"`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Process_Threads",
			Description: "Looks for a new process or thread being leveraged",
			Regex:       *regexp.MustCompile(`(?:new\s+process\(\)|startinfo\.(?:filename|UseShellExecute|Redirect(?:StandardInput|StandardOutput|StandardError)|CreateNoWindow)|WaitForExit())`),
			Attribute:   true,
		},
		{
			Name:        "ASP_Database",
			Description: "Looks for database access, imports and usage",
			Regex:       *regexp.MustCompile(`(?:(?:SqlDataAdapter|SqlConnection|SqlCommand)\(|System\.Data\.SqlClient|System\.Data\.OleDb|OleDbConnection\(\))`),
			Attribute:   true,
		},
	}

	//// JSP
	cm.GlobalMap.Tags_Jsp = []cm.TagDef{
		{
			Name:        "JSP_Execution",
			Description: "JSP functions associated with code execution",
			Regex:       *regexp.MustCompile(`(?i)(?:runtime\.exec\()`),
		},
	}

	//// CFM
	cm.GlobalMap.Tags_Cfm = []cm.TagDef{
		{
			Name:        "CFM_Execution",
			Description: "CFM functions associated with code execution",
			Regex:       *regexp.MustCompile(`(?i)(?:"?/c\s+"?'?#?cmd#?'?"?)`),
		},
	}
}

func main() {

	start := time.Now()
	var dir = flag.String("dir", "", "Directory to scan for web shells")
	var size = flag.Int64("size", 10, "Specify max file size to scan (default is 10 MB)")
	var verbose = flag.Bool("verbose", false, "If set to true, the analyzer will print all files analyzer, not just matches")
	var rawContents = flag.Bool("raw_contents", false, "If a match is found, grab the raw contents and base64 + gzip compress the file into the JSON object.")
	flag.Parse()

	if *dir == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	cm.VerboseMode = *verbose

	totalFilesScanned := 0

	var wg sync.WaitGroup
	for w := 1; w <= 1; w++ {
		wg.Add(1)
		go Scan_worker(&wg, *rawContents)
	}

	_ = filepath.Walk(*dir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !f.IsDir() {
			if f.Size() < (*size * 1024 * 1024) {
				cm.FilesToScan <- path
				totalFilesScanned = totalFilesScanned + 1
			}
		}
		return nil
	})

	close(cm.FilesToScan)
	wg.Wait()

	metrics := cm.Metrics{}
	metrics.Scanned = totalFilesScanned
	metrics.Clear = cm.Cleared
	metrics.Matched = cm.Matched
	metrics.ScannedDir = *dir
	metrics.ScanTime = time.Since(start).Minutes()

	// Items empty if error
	osName, _ := os.Hostname()
	envVars := os.Environ()
	theUser, _ := user.Current()

	metrics.SystemInfo.Hostname = osName
	metrics.SystemInfo.EnvVars = envVars
	metrics.SystemInfo.Username = theUser.Username
	metrics.SystemInfo.UserID = theUser.Uid
	metrics.SystemInfo.RealName = theUser.Name
	metrics.SystemInfo.UserHomeDir = theUser.HomeDir

	data, err := json.Marshal(metrics)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", data)
}
