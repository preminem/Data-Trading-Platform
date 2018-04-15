package main

import (
	"fmt"
	"io/ioutil"
)

func main() {
	cer, err := ioutil.ReadFile("./Admin@org2.example.com-cert.pem")
	certstring := string(cer)
	fmt.Println(certstring)
	if err != nil {
		fmt.Println("fuck!")
	}
}
