package db

import (
	"fmt"
	"github.com/go-redis/redis"
	"time"
)

type connect struct {
	db redis.Conn
}

var redisCon = &redis.Client{}

func init() {
	redisCon = redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379",
		DB:       0,
	})

	//ping
	_, err := redisCon.Ping().Result()
	if err != nil {
		fmt.Println("ping error", err.Error())
		return
	}
	//fmt.Println("ping result:", pong)
}

func Set(key ,value string)error {
	if err := redisCon.Set(key, value, 8760*time.Hour).Err();err != nil{
		fmt.Println("set err", err)
		return err
	}

	return nil
}

func Exists(keys string)bool  {
	ex,err := redisCon.Exists(keys).Result()
	if err != nil{
		fmt.Println("exist err",err)
	}
	if ex == 1 {
		return true
	}else {
		return false
	}
}


func Get(key string) (string,error) {
	value, err := redisCon.Get(key).Result()
	if err != nil {
		//fmt.Println("Get err", err)
		return "" ,err
	}
	return value,nil
}

