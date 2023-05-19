package utils

import (
	"math/rand"
	"time"
)

func RandomGenSleepTime() int {
	rand.Seed(time.Now().UnixNano())
	result := rand.Intn(10)
	return result
}
