package cliparser

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

type ActionInfo struct {
	Directive, InputPath, OutputPath, Password string
}

func getPasswordFromUser() (pass string, errr error) {
	fmt.Println("Enter Password: ")
	enteredPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	password := strings.Trim(string(enteredPassword), " ")

	return password, nil
}

func getOutputPath(dirc string, fp string) string {
	var oF string

	switch dirc {
	case "enc":
		oF = fp + ".enc"
	case "dec":
		oF = strings.TrimSuffix(fp, ".enc")
	}

	return oF
}

func CliParser(args []string) (ActionInfo, error) {

	const usage string = "Usage: secure-files-go <enc|dec> <input_file>"
	var directive string
	var outputFile string
	action := ActionInfo{}

	if len(args) < 2 {
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

	outputFile = getOutputPath(directive, fullInputPath)

	pw, err := getPasswordFromUser()

	if err != nil {
		return action, err
	}

	action.Directive = directive
	action.InputPath = fullInputPath
	action.OutputPath = outputFile
	action.Password = pw

	return action, nil
}
