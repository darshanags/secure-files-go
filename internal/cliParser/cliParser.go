package cliparser

import "errors"

func CliParser(args []string) error {

	const usage string = "Usage: secure-files <enc|dec> <input_file> <password>"

	if len(args) < 3 {
		return errors.New("insufficient arguments. " + usage)
	}

	if args[0] != "enc" && args[0] != "dec" {
		return errors.New("the directive argument is invalid")
	}

	return nil
}
