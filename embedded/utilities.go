package embedded

import "os"

func FileExits(filename string) bool {
	if f, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	} else if err == nil {
		return !f.IsDir()
	} else {
		return false
	}
}
