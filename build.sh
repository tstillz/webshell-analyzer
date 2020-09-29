#!/usr/bin/env bash

## Windows
GOOS=windows GOARCH=386 go build -o wsa32.exe main.go
GOOS=windows GOARCH=amd64 go build -o wsa64.exe main.go

## Linux
GOOS=linux GOARCH=amd64 go build -o wsa_linux64 main.go

## Darwin
GOOS=darwin GOARCH=amd64 go build -o wsa_darwin64 main.go
