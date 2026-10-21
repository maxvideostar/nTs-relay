#!/usr/bin/env bash
# Compilează StreamHub pentru Linux și Windows în dist/
set -euo pipefail
cd "$(dirname "$0")"
V=$(grep -o 'version = "[^"]*"' main.go | cut -d'"' -f2)
mkdir -p dist
export CGO_ENABLED=0
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/streamhub-linux-amd64 .
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/streamhub-linux-arm64 .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/streamhub.exe .
( cd dist && rm -f "streamhub-$V-windows-x64.zip" && cp ../CITESTE-Windows.txt . && zip -q "streamhub-$V-windows-x64.zip" streamhub.exe CITESTE-Windows.txt && rm CITESTE-Windows.txt )
ls -la dist
