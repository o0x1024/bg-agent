package utils

import "os"

func CheckFileIsExist(filename string) (bool) {
	var flag = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		flag = false
	}
	return flag
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}