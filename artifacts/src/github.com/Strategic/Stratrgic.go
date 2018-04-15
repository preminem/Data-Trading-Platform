package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
)

type SmartContract struct {
}

type Record struct {
	User      string   `json:"user"`
	Times     int      `json:"times"`
	Timestamp []string `json:"timestamp"`
}

type API struct {
	Id          int      `json:"id"`
	Url         string   `json:"url"`
	Owner       string   `json:"owner`
	Certificate string   `json:"certificate"`
	Summarize   string   `json:"summarize`
	Authority   []string `json:"authority"`
	Record      []Record `json:"record"`
}

//记录API的数量，用来当做API的ID
type APInumber struct {
	Number int `json:"number"`
}

func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	zeroAsBytes, _ := json.Marshal(0)
	APIstub.PutState("APINUMBER", zeroAsBytes)
	return shim.Success(nil)
}

func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {

	function, args := APIstub.GetFunctionAndParameters()

	if function == "queryAPIbyID" {
		return s.queryAPIbyID(APIstub, args)
	} else if function == "queryAllAPI" {
		return s.queryAllAPI(APIstub, args)
	} else if function == "queryAPIbyOwner" {
		return s.queryAPIbyOwner(APIstub, args)
	} else if function == "queryAPIbySummarize" {
		return s.queryAPIbySummarize(APIstub, args)
	} else if function == "submitAPI" {
		return s.submitAPI(APIstub, args)
	} else if function == "getAuthority" {
		return s.getAuthority(APIstub, args)
	} else if function == "requestAPI" {
		return s.requestAPI(APIstub, args)
	}
	return shim.Error("Invalid Smart Contract function name.")
}

func (s *SmartContract) queryAPIbyID(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}
	apiAsBytes, _ := APIstub.GetState(args[0])
	return shim.Success(apiAsBytes)
}

func (s *SmartContract) queryAllAPI(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	queryString := "{\"selector\":{\"id\":{\"$gt\":0}}}"
	return shim.Success(richQuery(APIstub, queryString))
}

func (s *SmartContract) queryAPIbyOwner(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}
	queryString := fmt.Sprintf("{\"selector\":{\"Owner\":\"%s\"}}", args[0])
	return shim.Success(richQuery(APIstub, queryString))
}

func (s *SmartContract) queryAPIbySummarize(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}
	queryString := fmt.Sprintf("{\"selector\":{\"Summarize\":{\"$regex\":\"(?i)%s\"}}}", args[0])
	return shim.Success(richQuery(APIstub, queryString))
}

func (s *SmartContract) submitAPI(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}
	//提取证书
	creatorByte, _ := APIstub.GetCreator()
	certStart := bytes.IndexAny(creatorByte, "-----BEGIN")
	if certStart == -1 {
		return shim.Error("No certificate found")
	}
	certText := creatorByte[certStart:]
	certstring := string(certText)
	//提取用户身份
	bl, _ := pem.Decode(certText)
	if bl == nil {
		return shim.Error("Could not decode the PEM structure")
	}
	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return shim.Error("ParseCertificate failed")
	}
	uname := cert.Subject.CommonName
	//提取API个数
	numberAsBytes, _ := APIstub.GetState("APINUMBER")
	number := APInumber{}
	json.Unmarshal(numberAsBytes, &number)
	newnumber := number.Number + 1
	//提交API信息
	var api = API{Id: newnumber, Url: args[0], Owner: uname, Certificate: certstring, Summarize: args[1]}
	apiAsBytes, _ := json.Marshal(api)
	APIstub.PutState("API"+strconv.Itoa(newnumber), apiAsBytes)
	//更新API个数
	number.Number = newnumber
	numberAsBytes, _ = json.Marshal(number)
	APIstub.PutState("APINUMBER", numberAsBytes)
	return shim.Success(nil)
}

func (s *SmartContract) getAuthority(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}
	//提取API信息
	apiAsBytes, _ := APIstub.GetState(args[0])
	api := API{}
	json.Unmarshal(apiAsBytes, &api)
	//提取用户身份
	creatorByte, _ := APIstub.GetCreator()
	certStart := bytes.IndexAny(creatorByte, "-----BEGIN")
	if certStart == -1 {
		return shim.Error("No certificate found")
	}
	certText := creatorByte[certStart:]
	bl, _ := pem.Decode(certText)
	if bl == nil {
		return shim.Error("Could not decode the PEM structure")
	}

	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return shim.Error("ParseCertificate failed")
	}
	uname := cert.Subject.CommonName
	//验证是否有权限
	for _, name := range api.Authority {
		if name == uname {
			return shim.Error("Already have authority!")
		}
	}
	//增加权限，提交API信息
	upAPI := API{Id: api.Id, Url: api.Url, Owner: api.Owner, Certificate: api.Certificate, Summarize: api.Summarize, Authority: append(api.Authority, uname), Record: api.Record}
	apiAsBytes, _ = json.Marshal(upAPI)
	APIstub.PutState(args[0], apiAsBytes)
	return shim.Success(nil)
}

//参数1：APIID 参数2：ReqSigR 参数3：ReqSigS
//最后的请求体再加上自己的证书Reqcert、用户名（admin.org1.example.com)
func (s *SmartContract) requestAPI(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments. Expecting 3")
	}
	//提取API信息
	apiAsBytes, _ := APIstub.GetState(args[0])
	api := API{}
	json.Unmarshal(apiAsBytes, &api)
	//提取证书
	creatorByte, _ := APIstub.GetCreator()
	certStart := bytes.IndexAny(creatorByte, "-----BEGIN")
	if certStart == -1 {
		return shim.Error("No certificate found")
	}
	certText := creatorByte[certStart:]
	certstring := string(certText)
	certstring = strings.Replace(certstring, "\n", "\\n", -1)
	//提取请求方身份
	bl, _ := pem.Decode(certText)
	if bl == nil {
		return shim.Error("Could not decode the PEM structure")
	}
	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return shim.Error("ParseCertificate failed")
	}
	uname := cert.Subject.CommonName
	//验证是否有权限
	var flag = false
	for _, name := range api.Authority {
		if name == uname {
			flag = true
			break
		}
	}
	if flag == false {
		return shim.Error("No permission to call this API!")
	}
	//开始请求
	quertString := fmt.Sprintf("{\"APIID\":\"%s\",\"ReqSigR\":\"%s\",\"ReqSigS\":\"%s\",\"ReqCert\":\"%s\",\"Uname\":\"%s\"}", args[0], args[1], args[2], certstring, uname)
	var jsonStr = []byte(quertString)
	req, err := http.NewRequest("POST", api.Url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return shim.Error("Request err!")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
		return shim.Error("Response err!")
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	//提交API信息
	timestamp, _ := APIstub.GetTxTimestamp()
	a := timestamp.Seconds
	timestring := time.Unix(a, 0).String()
	flag = false
	upAPI := API{}
	for i, record := range api.Record {
		if record.User == uname {
			newrecord := Record{User: record.User, Times: record.Times + 1, Timestamp: append(record.Timestamp, timestring)}
			api.Record[i] = newrecord
			upAPI = API{Id: api.Id, Url: api.Url, Owner: api.Owner, Certificate: api.Certificate, Summarize: api.Summarize, Authority: api.Authority, Record: api.Record}
			flag = true
			break
		}
	}
	if flag == false {
		newrecord := Record{User: uname, Times: 1, Timestamp: []string{timestring}}
		upAPI = API{Id: api.Id, Url: api.Url, Owner: api.Owner, Certificate: api.Certificate, Summarize: api.Summarize, Authority: api.Authority, Record: append(api.Record, newrecord)}
	}
	apiAsBytes, _ = json.Marshal(upAPI)
	APIstub.PutState(args[0], apiAsBytes)

	return shim.Success(body)
}

func richQuery(APIstub shim.ChaincodeStubInterface, querystring string) []byte {
	resultsIterator, err := APIstub.GetQueryResult(querystring)
	if err != nil {
		return []byte(err.Error())
	}
	defer resultsIterator.Close()
	var buffer bytes.Buffer
	buffer.WriteString("[")
	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return []byte(err.Error())
		}
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")

		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")
	fmt.Printf("- API query results:\n%s\n", buffer.String())
	return buffer.Bytes()
}

func main() {
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}
}
