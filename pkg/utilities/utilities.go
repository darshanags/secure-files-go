package utilities

import "fmt"

type FileInfo struct {
	InputFilename, InputPath, OutputFilename, OutputPath string
}

type AsyncResult struct {
	Filename string
	Message  string
	Error    error
}

func FormatFileSize(s float64) string {
	const base float64 = 1024

	var sizes = []string{"B", "kB", "MB", "GB", "TB", "PB", "EB"}
	var unitsLimit uint8 = uint8(len(sizes))
	var i uint8 = 0

	for s >= base && i < unitsLimit {
		s = s / base
		i++
	}

	f := "%.0f %s"
	if i > 1 {
		f = "%.2f %s"
	}

	return fmt.Sprintf(f, s, sizes[i])
}
