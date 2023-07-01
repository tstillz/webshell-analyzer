#!/usr/bin/env bash

## Windows
GOOS=windows GOARCH=386 go build -ldflags "-s -w" -o bins/wsa32.exe cmd/main.go
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bins/wsa64.exe cmd/main.go

## Linux
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bins/wsa_linux64 cmd/main.go

## Darwin
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bins/wsa_darwin64 cmd/main.go
