package util

import (
	"errors"
	"os"
	"strconv"
)

func EnvBool(s string) bool {
	v := os.Getenv(s)
	if len(v) == 0 {
		return false
	}

	return v == "1" || v == "true" || v == "True" || v == "yes"
}

func EnvInt(s string) (int, error) {
	v := os.Getenv(s)
	if len(v) == 0 {
		return 0, errors.New("no value")
	}

	var vi int
	var err error
	if vi, err = strconv.Atoi(v); err != nil {
		return 0, err
	}

	return vi, nil
}
