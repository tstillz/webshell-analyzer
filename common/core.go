package common

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

var (
	FilesToScan = make(chan string, 1000)
	GlobalMap   = Config{}
	Matched     = 0
	Cleared     = 0
	VerboseMode = false
)

func checkRegexMatches(tagItems [][]TagDef, tags map[string]map[string]int, data string, fileMatches map[string]int) (map[string]int, map[string]map[string]int) {
	/// loop over the content and check for tag matches
	for _, tI := range tagItems {
		for _, t := range tI {

			tagMatches := t.Regex.FindAllString(data, -1)
			if len(tagMatches) > 0 {
				for _, tm := range tagMatches {
					if tm == "" { // Exclude empty hits
						continue
					}

					// Always do some defanging here for http/s
					if strings.ContainsAny(tm, "http") {
						tm = strings.Replace(tm, ".", "[.]", -1)
						tm = strings.Replace(tm, "http", "hxxp", -1)
						tm = strings.Replace(tm, "://", ":\\", -1)
					}

					// We don't want items that are only attributes creating a detection
					if t.Attribute == false {
						//fmt.Println("[X] Matcher: ", tm)
						if _, ok := fileMatches[tm]; ok {
							fileMatches[tm] = fileMatches[tm] + 1
						} else {
							fileMatches[tm] = 1
						}
					}

					// Breakdown the tags into a subgroup
					if _, ok := tags[t.Name]; ok {
						if _, ok := tags[t.Name][tm]; ok {
							tags[t.Name][tm] = tags[t.Name][tm] + 1
						} else {
							tags[t.Name][tm] = 1
						}
					} else {
						tags[t.Name] = map[string]int{}
						tags[t.Name][tm] = 1
					}
				}
			}
		}
	}

	return fileMatches, tags
}
func runActionFunctions(functions []Action, rawBytes []byte) ([]byte, bool, error) {
	changed := false
	sHash := GetSHA1Hash(rawBytes)

	if len(functions) > 0 {
		for _, action := range functions {
			decoded, err := action.Function(rawBytes, action.Arguments)
			if err != nil {
				return rawBytes, false, err
			}
			rawBytes = decoded
		}
	}

	fHash := GetSHA1Hash(rawBytes)
	if sHash != fHash {
		changed = true
	}
	return rawBytes, changed, nil
}
func runDecodingFunctions(functions []Base_Func, rawBytes []byte) ([]byte, error) {

	rawContent := rawBytes
	for _, deobfuscationFunction := range functions {
		newContent, err := deobfuscationFunction(rawContent)
		if len(newContent) == 0 {
			return newContent, nil
		}

		if err != nil {
			return newContent, err
		}
		rawContent = []byte(newContent)
	}

	return rawContent, nil
}
func ProcessFileData(data string, fileExt string) (fileMatches map[string]int, decodes map[string]int, tags map[string]map[string]int) {

	starttime := time.Now().Unix()
	killswitch := false

	var decoderChan = make(chan []byte, 10000)
	decoderChan <- []byte(data)

	decoders := [][]RegexDef{}
	tagItems := [][]TagDef{}

	decoders = append(decoders, GlobalMap.Function_Generics)
	tagItems = append(tagItems, GlobalMap.Tags_Generics)

	fileMatches = make(map[string]int)
	decodes = make(map[string]int)
	tags = make(map[string]map[string]int)

	switch strings.ToLower(fileExt) {

	case ".php":
		decoders = append(decoders, GlobalMap.Function_Php)
		tagItems = append(tagItems, GlobalMap.Tags_Php)

	case ".asp":
		decoders = append(decoders, GlobalMap.Function_Asp)
		tagItems = append(tagItems, GlobalMap.Tags_Asp)

	case "aspx":
		decoders = append(decoders, GlobalMap.Function_Asp)
		tagItems = append(tagItems, GlobalMap.Tags_Asp)

	case ".jsp":
		decoders = append(decoders, GlobalMap.Function_Jsp)
		tagItems = append(tagItems, GlobalMap.Tags_Jsp)

	case "jspx":
		decoders = append(decoders, GlobalMap.Function_Jsp)
		tagItems = append(tagItems, GlobalMap.Tags_Jsp)

	case ".cfm":
		decoders = append(decoders, GlobalMap.Function_Cfm)
		tagItems = append(tagItems, GlobalMap.Tags_Cfm)

	default:
		return
	}

	for d := range decoderChan {

		currentTime := time.Now().Unix()
		if currentTime-starttime > 90 && killswitch == false { // max second loop time before we stop putting items on the queue
			killswitch = true
		}

		// Use our regex to get any initial matches before decoder analysis
		fileMatches, tags = checkRegexMatches(tagItems, tags, string(d), fileMatches)

		// Todo handle non-UTF8 encoding
		//if !utf8.ValidString(fmt.Sprintf("%s", d)) {
		//	fmt.Println("!utf8.ValidString")
		//}

		for _, decoder := range decoders {
			for _, dec := range decoder {
				obfuscatedMatches := dec.Regex.FindAllString(string(d), -1)

				if len(obfuscatedMatches) > 0 {

					for _, om := range obfuscatedMatches {
						dataCapture := dec.DataCapture.FindAllString(om, -1)
						if len(dataCapture) > 0 {

							for _, dataCaptureMatches := range dataCapture {

								//// Run any preActionFunctions:
								changedBytes, _, err := runActionFunctions(dec.PreDecodeActions, []byte(dataCaptureMatches))
								if err != nil {
									fmt.Println("err", err)
									continue
								}

								decodedContent, decoderErr := runDecodingFunctions(dec.Functions, []byte(changedBytes))
								if decoderErr != nil {
									continue

								} else if len(decodedContent) == 0 {
									continue

								} else if string([]byte(dataCaptureMatches)) == string(decodedContent) {
									continue

								} else {
									// Run any postActionFunctions:
									rawBytesPost, changed, err := runActionFunctions(dec.PostDecodeActions, []byte(decodedContent))
									if err != nil {
										continue
									}

									// After decoding, we run through the defined decoding functions for the decoder
									// Note: Decoder mods can mess with the matcher, such as url defanging..
									// If the post-actions change the content, requeue it for processing
									if changed == true {
										if killswitch == false {
											decoderChan <- rawBytesPost
										}
									}

									if _, ok := decodes[dec.Name]; ok {
										decodes[dec.Name] = decodes[dec.Name] + 1
									} else {
										decodes[dec.Name] = 1
									}

									// Run the match engine again over the decoded data
									fileMatches, tags = checkRegexMatches(tagItems, tags, string(decodedContent), fileMatches)
									// Kill switch ensures we have a limit for adding new queue items per each file. After kill switch it true, we stop queueing items per file
									if killswitch == true {
										continue
									} else {
										decoderChan <- decodedContent // Since the decoded content != rawbytes, the decoder changed something.
									}
								}
							}
						}
					}
				}
			}
		}

		if len(decoderChan) == 0 {
			close(decoderChan)
			break
		}
	}

	return fileMatches, decodes, tags
}
func ProcessFile(j string) (fileMatches, functions map[string]int, size int64, tags map[string]map[string]int) {

	fileHandle, err := os.Open(j)
	if err != nil {
		log.Fatal(err)
	}
	defer fileHandle.Close()

	fi, err := os.Stat(j)
	if err != nil {
		log.Println(err)
	}

	fileScanner := bufio.NewScanner(fileHandle)

	data := ""
	for fileScanner.Scan() {
		data = data + fileScanner.Text()
	}

	fileExt := j[len(j)-4:]

	matches, functions, tags := ProcessFileData(data, strings.ToLower(fileExt))

	return matches, functions, fi.Size(), tags

}
func Md5HashFile(filePath string) (string, error) {
	var hashString string
	file, err := os.Open(filePath)
	if err != nil {
		return hashString, err
	}
	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return hashString, err
	}
	hashInBytes := hash.Sum(nil)
	hashString = hex.EncodeToString(hashInBytes)
	return hashString, nil
}
func SHA1HashFile(filePath string) (string, error) {
	var hashString string
	file, err := os.Open(filePath)
	if err != nil {
		return hashString, err
	}
	defer file.Close()
	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return hashString, err
	}
	hashInBytes := hash.Sum(nil)
	hashString = hex.EncodeToString(hashInBytes)
	return hashString, nil
}
func SHA256HashFile(filePath string) (string, error) {
	var hashString string
	file, err := os.Open(filePath)
	if err != nil {
		return hashString, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return hashString, err
	}
	hashInBytes := hash.Sum(nil)
	hashString = hex.EncodeToString(hashInBytes)
	return hashString, nil
}
func GetSHA1Hash(data []byte) string {
	h := sha1.New()
	h.Write(data)
	bs := h.Sum(nil)
	hashItem := fmt.Sprintf("%x\n", bs)
	return hashItem
}
func CompressEncode(filePath string, fileSize int64) string {

	fileItem, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer fileItem.Close()

	buf := make([]byte, fileSize)
	fReader := bufio.NewReader(fileItem)
	fReader.Read(buf)

	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(buf); err != nil {
		return ""
	}
	if err := gz.Flush(); err != nil {
		return ""
	}
	if err := gz.Close(); err != nil {
		return ""
	}

	readBuf, _ := ioutil.ReadAll(&b)
	imgBase64Str := base64.StdEncoding.EncodeToString(readBuf)

	return imgBase64Str

}
