package cliparser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type ActionInfo struct {
	Directive, InputPath, OutputPath, Password string
}

func CliParser(args []string) (ActionInfo, error) {

	const usage string = "Usage: secure-files <enc|dec> <input_file> <password>"
	var directive string
	var outputFile string
	action := ActionInfo{}

	if len(args) < 3 {
		return action, errors.New("insufficient arguments. " + usage)
	}

	if args[0] != "enc" && args[0] != "dec" {
		return action, errors.New("the directive argument is invalid")
	} else {
		directive = args[0]
	}

	inputFileInfo, err := os.Stat(args[1])
	if err != nil {
		return action, err
	}

	if inputFileInfo.IsDir() {
		return action, errors.New("input_file cannot be a directory")
	}

	fullInputPath, err := filepath.Abs(args[1])

	if err != nil {
		return action, err
	}

	if args[0] == "dec" && filepath.Ext(args[1]) != ".enc" {
		return action, errors.New("the input file extension is invalid")
	}

	switch args[0] {
	case "enc":
		outputFile = fullInputPath + ".enc"
	case "dec":
		outputFile = strings.TrimSuffix(fullInputPath, ".enc")
	}

	action.Directive = directive
	action.InputPath = fullInputPath
	action.OutputPath = outputFile
	action.Password = args[2]

	return action, nil
}
