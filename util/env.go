package util

func EnvBool(s string) bool {
	return s == "1" || s == "true" || s == "True" || s == "yes"
}
