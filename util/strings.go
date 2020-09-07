package util

// StringInSlice looks for a string in a slice
func StringInSlice(slice []string, s string) bool {
	for _, ss := range slice {
		if s == ss {
			return true
		}
	}
	return false
}
