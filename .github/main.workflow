name: Test

on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]

jobs:

  build:
    name: Build
    runs-on: ubuntu-latest
    steps:

    - name: Set up Go 1.14
      uses: actions/setup-go@v1
      with:
        go-version: 1.14
      id: go

    - name: Check out code into the Go module directory
      uses: actions/checkout@v2

    - name: Generate
      run: go generate ./...

    - name: Test
      run: go test -race ./...
  
