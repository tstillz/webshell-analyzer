package common

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var DecodeBase64 Base_Func = func(data []byte, args ...interface{}) (content []byte, err error) {
	//fmt.Println("Running de-obfuscation: b64_decode")
	//fmt.Println("BEFORE b64_decode", string(data))

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	//fmt.Println(err)
	//fmt.Println(string(decoded))
	if err != nil {
		//fmt.Println("error in b64", err)
		return
	}

	return decoded, err
}
var GZInflate Base_Func = func(data []byte, args ...interface{}) (content []byte, err error) {
	//fmt.Println("Running de-obfuscation: gzinflate")
	//fmt.Println("Bytes: ", data)
	//fmt.Printf("Hex: %x\n", data[2:])

	content, err = ioutil.ReadAll(flate.NewReader(bytes.NewReader(data)))
	if err != nil {
		//fmt.Println("error gzinflate")
		return
	}

	//fmt.Println("AFTER GZ", string(content))

	return content, err
}
var UrlDecode Base_Func = func(data []byte, args ...interface{}) (content []byte, err error) {
	decodedString, err := url.QueryUnescape(string(data))
	if err != nil {
		return
	}
	//fmt.Println("Got url decode to: ", decodedString)
	b := []byte(decodedString)
	return b, err
}
var StringReplace Base_Func = func(data []byte, args ...interface{}) (content []byte, err error) {
	HelperName := "StringReplace"

	if len(args) != 1 {
		return content, fmt.Errorf("[%s]: Bad number of main arguments: %v\n", HelperName, args)
	}

	rootArgs := args[0].([]interface{})
	if len(rootArgs) != 3 {
		return content, fmt.Errorf("[%s]: Bad number of root arguments: %v\n", HelperName, rootArgs)
	}

	//fmt.Printf("Running helper: %s with args of: %v\n", HelperName, rootArgs)
	//fmt.Println("The total args are: ", len(rootArgs))

	// We should check if the types are indeed as required. aka args[0]==string before casting else app may crash
	if reflect.TypeOf(rootArgs[0]).Kind() != reflect.String || reflect.TypeOf(rootArgs[1]).Kind() != reflect.String || reflect.TypeOf(rootArgs[2]).Kind() != reflect.Int {
		return content, fmt.Errorf("[%s]: Bad type found in arguments: %v\n", HelperName, rootArgs)
	}

	cleanedItem := strings.Replace(string(data), rootArgs[0].(string), rootArgs[1].(string), rootArgs[2].(int))
	b := []byte(cleanedItem)
	return b, err
}
var StringReplaceRegex Base_Func = func(data []byte, args ...interface{}) (content []byte, err error) {
	HelperName := "StringReplaceRegex"

	if len(args) != 1 {
		return content, fmt.Errorf("[%s]: Bad number of main arguments: %v\n", HelperName, args)
	}

	rootArgs := args[0].([]interface{})
	if len(rootArgs) != 3 {
		return content, fmt.Errorf("[%s]: Bad number of root arguments: %v\n", HelperName, rootArgs)
	}

	//fmt.Printf("Running helper: %s with args of: %v\n", HelperName, rootArgs)
	//fmt.Println("The total args are: ", len(rootArgs))

	// We should check if the types are indeed as required. aka args[0]==string before casting else app may crash
	if reflect.TypeOf(rootArgs[0]).Kind() != reflect.String || reflect.TypeOf(rootArgs[1]).Kind() != reflect.String || reflect.TypeOf(rootArgs[2]).Kind() != reflect.Int {
		return content, fmt.Errorf("[%s]: Bad type found in arguments: %v\n", HelperName, rootArgs)
	}

	//fmt.Println(rootArgs[0].(string))

	regexItem, err := regexp.Compile(rootArgs[0].(string))
	if err != nil {
		return
	}

	res := regexItem.ReplaceAllString(string(data), ``)

	b := []byte(res)
	return b, err
}
var CharDecode Base_Func = func(data []byte, args ...interface{}) (content []byte, err error) {
	//HelperName := "CharDecode"
	//fmt.Println("running charcode")

	cleanedItem := []string{}
	items := strings.Split(string(data), "|")
	for _, i := range items {
		getInt, err := strconv.Atoi(i)
		if err != nil {
			continue
		}
		ch := rune(getInt)
		cleanedItem = append(cleanedItem, fmt.Sprintf("%c", ch))
	}

	joinedItems := strings.Join(cleanedItem, "")
	if len(joinedItems) == 0 {
		return data, err
	} else {
		return []byte(joinedItems), err
	}
}

func FormatTimestamp(dts time.Time) (cts string) {
	cts = dts.Format("2006-01-02 15:04:05")
	return cts
}
