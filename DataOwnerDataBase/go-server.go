package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
)

type Request struct {
	APIID   string `json:"APIID"`
	ReqSigR string `json:"ReqSigR"`
	ReqSigS string `json:"ReqSigS"`
	ReqCert string `json:"ReqCert"`
	Uname   string `json:"Uname"`
}

func main() {
	http.HandleFunc("/abc", handler)
	http.ListenAndServe(":9001", nil)
}
func handler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm() //解析参数，默认是不会解析的
	if r.Method == "GET" {
		fmt.Println("method:", r.Method) //获取请求的方法
		fmt.Println("username", r.Form["username"])
		fmt.Println("password", r.Form["password"])
		for k, v := range r.Form {
			fmt.Print("key:", k, "; ")
			fmt.Println("val:", strings.Join(v, ""))
		}
	} else if r.Method == "POST" {
		result, _ := ioutil.ReadAll(r.Body)
		fmt.Printf("%s\n", result)
		//未知类型的推荐处理方法
		var req Request
		json.Unmarshal([]byte(result), &req)
		//从本地查找是否有满足权限的用户证书
		path := fmt.Sprintf("./%s-cert.pem", req.Uname)
		fmt.Println(path)
		certbyte, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Println("fuck!")
			fmt.Fprintf(w, "DataOwner don't have your Certificate!")
			r.Body.Close()
		}
		cer := string(certbyte)
		//从证书中提取公钥
		block, _ := pem.Decode([]byte(cer))
		if block == nil {
			fmt.Fprintf(w, "block nil!")
			r.Body.Close()
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(w, "x509 parse err!")
			r.Body.Close()
		}
		pub := cert.PublicKey.(*ecdsa.PublicKey)
		//开始验证
		var mm, nn big.Int
		var rr, ss *big.Int
		strdata := fmt.Sprintf("{\"APIID\":%s,\"Certificate\":%s}", req.APIID, cer)
		fmt.Println(strdata)
		h2 := sha256.New()
		h2.Write([]byte(strdata))
		hashed := h2.Sum(nil)
		mm.SetString(req.ReqSigR, 10) //大于int64的数字要用到SetString函数
		nn.SetString(req.ReqSigS, 10)
		rr = &mm
		ss = &nn
		end := ecdsa.Verify(pub, hashed, rr, ss)
		if end != true {
			fmt.Fprintf(w, "Verification failed")
			r.Body.Close()
		}
		fmt.Println("权限验证成功！")
		fmt.Fprintf(w, "这是一个月以来的钢铁市场数据")
		r.Body.Close()

	}
}
