#!/usr/bin/env bash
echo "gomobile bind -x -v -target=android"
gomobile bind -x -v -o ./build/android/gomobile.aar -target=android -ldflags -w
echo "gomobile bind -x -v -target=ios"
gomobile bind -x -v -o ..build/ios/Gomobile.framework -target=ios -ldflags -w
