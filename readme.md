# Web Shell Analyzer
Web shell analyzer is a cross platform stand-alone binary built solely for the purpose of identifying, decoding, and tagging files that are suspected to be web shells. The web shell analyzer is the bigger brother to the web shell scanner project (http://github.com/tstillz/webshell-scan),
which only scans files via regex, no decoding or attribute analysis. 

### Disclaimer
The regex and its built-in decoding routines supplied with the scanner are not guaranteed to find every web shell on disk and maybe identify some false positives. It's also recommended you test the analyzer and assess its impact before running on production systems.
The analyzer has no warranty, use as your own risk.

### Features

- Cross platform, statically compiled binary. 
- JSON output
- Currently supports most `PHP`, `ASP/X` web shells. `JSP/X`, `CFM` and other types are in the works.
- Recursive, multi-threaded scanning capable of iterating through nested directories quickly
- Ability to handle multiple layers of obfuscated web shells such as base64, gzinflate and char code.
- Supports PRE/POST actions which powers layered de-obfuscated and decoding for the analysis engine
- Tunable regex logic with modular interfaces to easily extend the analyzers capabilities
- Tunable attribute tagging
- Raw content captures upon match
- System Info
- Tested against the web shell repo: https://github.com/tennc/webshell
 
#### PRE/POST Actions
Every file that is scanned can be run through PRE and/or POST action:
- PRE-Decoding: Functions invoked BEFORE matching is performed, such as base64 decoding or string replacement.
- POST-Decoding: Functions invoked AFTER matching is performed, such as url defanging.

The idea behind `PreDecodeActions` functions were to use regex to identify a matching string or pattern, acquire its raw match contents, perform defined decoding/cleanup steps and send the final output back to the analysis engine for re-scanning/processing. 
A very simple example of this is Base64 decoding. In order to check for any detection logic against a base64 encoded web shell, we must first remove any/all layers of base64. Todo this, we could use the following PreDecodeAction:
```
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
```

Looking at the block above, we first have the name of the function, the regex used to match, data capture regex (sometimes you may want to tweak what to capture vs what matches) and `PreDecodeActions`. In this case, BEFORE the function `cm.DecodeBase64` is applied to the matching text, the system will first remove the following items `"` and `'`.
`PostDecodeActions` works the opposite, where the output is checked AFTER decoding is performed. Using this model, we can make multiple custom decoders that have infinite PRE/POST and decoding functions to handle most web shell analysis needs.

#### Detections
A detection is a regex accompanied by a name and description. The idea behind this model was to make detections modular and scalable and kept context with the actual detection. 
Detections share the same format as attributes, minus attributes cannot generate a detection, they can only add context to an *existing* detection. Lets look at the example detect logic block below:
``` 
{
    Name:        "Generic_Embedded_Executable",
    Description: "Looks for magic bytes associated with a PE file",
    Regex:       *regexp.MustCompile(`(?i)(?:(?:0x)?4d5a)`),
},
```
Based on the regex, we can see its looking for an embedded Windows PE file based off the magic header bytes `4D 5A`. If found, this would lead to a detection and a JSON report would be generated for the file.
Currently, detections are applied based on file extension or generically for all file types. For example, decoding routines for PHP are defined under `cm.GlobalMap.Function_Php` and tags for either attributes are defined under `cm.GlobalMap.Tags_Php`.
The functions `cm.GlobalMap.Function_Generics` and tags under `cm.GlobalMap.Tags_Generics` apply to ALL web shell extensions as a catch all.

#### Attributes
Attribute tagging is a new concept I created that adds "context" to an existing web shell detection. Attributes alone *cannot* currently generate a detection on their own. In a traditional scan engine, a scanner would only alert if a web shell was detected
but provide little to no additional context into what capabilities (attributes) the web shell potentially has. Attribute tags work the same as detection logic, however they only show after a detection has been identified and cannot 
generate detections on their own. Looking at the example logic below:
```
cm.GlobalMap.Tags_Php = []cm.TagDef{
    {
        Name:        "PHP_Database_Operations",
        Description: "Looks for common PHP functions used for interacting with a database.",
        Regex:       *regexp.MustCompile(`(?i)(?:'mssql_connect\|mysql_exec\()`),
        Attribute: 	 true,
    },
}
```

We see that under the struct `Tags_Php`, we have created a new PHP tag. When a match is found during scanning, the `Attribute` flag is checked and if set to `True`, the detected web shell will have the tag
`PHP_Database_Operations` appended to its JSON report along with the frequency and matching text block, as shown in the example output below:

```
{
   "filePath": "/testers/1.php",
   "size": 66109,
   "md5": "6793d8ebab93e5a0f91e5a331221f331",
   "timestamps": {
      "birth": "2019-02-03 02:02:22",
      "created": "2020-07-29 02:50:15",
      "modified": "2019-02-03 02:02:22",
      "accessed": "2020-07-29 02:51:07"
   },
   "matches": {
      "FilesMAn": 5,
      "FilesMan": 29,
      "cmd": 20,
      "eval(": 4,
      "exec(": 2,
      "ipconfig": 1,
      "netstat": 2,
      "passthru(": 1,
      "shell_exec(": 1
   },
   "decodes": {
      "Generic_Base64Decode": 40,
      "Generic_Multiline_Base64Decode": 165
   },
   "tags": {
      "Generic_Embedding_Code_C": {
         "bind(": 2,
         "listen(": 2
      },
      "PHP_Banned_Function": {
         "exec(": 3,
         "get_current_user(": 1,
         "getmyuid(": 1,
         "link(": 7,
         "listen(": 2,
         "passthru(": 1,
         "realpath(": 1,
         "set_time_limit(": 1
      },
      "PHP_Database_Operations": {
         "mysql_query(": 1
      },
      "PHP_Disk_Operations": {
         "@chmod(": 1,
         "@filegroup(": 4,
         "@fileowner(": 4,
         "@rename(": 2,
         "fopen(": 7,
         "fwrite(": 6
      }
   }
}
```

These tags not only help define what a web shell can do, but it helps teams such as IR consultants performing live response engagements a pivot point into where to potentially look next.
 
### Requirements
None! Simply download the binary for your OS, supply the directory you wish to scan (other arguments are optional) and let it rip.

### Running the binary
Running `wsa` with no arguments shows the following options:

	/Users/beastmode$ ./wsa
	Options:
	    -dir string
          	Directory to scan for web shells
        -raw_contents
          	If a match is found, grab the raw contents and base64 + gzip compress the file into the JSON object.
        -size int
          	Specify max file size to scan (default is 10 MB) (default 10)
        -verbose bool
            If set to true, the analyzer will print all files analyzer, not just matches
            
The only required argument is `dir`. You can override the other program defaults if you wish. 
	
The output of the analyser will be written to console (standard output). Example below (For best results, send stdout to a json file and review/post process offline):

	Linux: ./wsa -dir /opt/www
	Windows: wsa.exe -dir C:\Windows\Inetput\wwwroot

    ### With STDOUT and full web shell file encoded and compressed:
    Linux: ./wsa -dir /opt/www -raw_contents=true > scan_results.json

Once the analyzer finishes, it will output the overall scan metrics to STDOUT, as shown in the example below:

   `{"scanned":311,"matches":122,"noMatches":189,"directory":"/webshell-master/php","scanDuration":1.4757737378333333,"systemInfo":{"hostname":"Beast","envVars":[""],"username":"beastmode","userID":"501","realName":"The Beast","userHomeDir":"/Users/beastmode"}}`

### Building the project from source
If you decide to modify the source code, you can build the project using the following commands:

    cd <path-to-project>
    
    ## Windows
    GOOS=windows GOARCH=386 go build -o wsa32.exe main.go
    GOOS=windows GOARCH=amd64 go build -o wsa64.exe main.go
    
    ## Linux
    GOOS=linux GOARCH=amd64 go build -o wsa_linux64 main.go
    
    ## Darwin
    GOOS=darwin GOARCH=amd64 go build -o wsa_darwin64 main.go

