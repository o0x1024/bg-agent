package db

import (
	"fmt"
	"github.com/garyburd/redigo/redis"
	"log"
	"regexp"
	"testing"
)

func TestGet(t *testing.T) {

	ex,err := redisCon.Exists("123").Result()
	if err != nil{
		fmt.Println("err",err)
	}
	fmt.Println(ex)

}

func TestSet(t *testing.T) {
	s := "eqweqw {{__abWWWc__}} {{.}}  {{.wqd}} {{__abc__}}  qwgkljgkldrt ejwlrk erkljyrtlyhr 4j23i5j3094 jew::_kjtwiu_dfjigsji"

	compile := regexp.MustCompile(`{{__(.*?)__}}`)

	submatch := compile.FindAllStringSubmatch(s, -1)

	for _,v:=range submatch{
		fmt.Println(v[1])
	}
	//fmt.Println(submatch)
}

func TestReids(t *testing.T) {
	log.Println(" init redis.")
	var err error
	con, err := redis.Dial("tcp", "127.0.0.1:6379")
	if err != nil {
		log.Println("Connect to redis error", err)
		return
	}
	defer con.Close()

	_, err = con.Do("SET", "test", "Test")
	if err != nil {
		log.Println("redis set failed:", err)
		return
	}


	data, err := redis.String(con.Do("GET", "test"))

	if err != nil {
		log.Println("redis get failed:", err)
		return
	}
	fmt.Println(data)
}

