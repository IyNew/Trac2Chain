package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"time"
)

var testNum int = 10
var testTreeNum int = 10
var straightTreeNum int = 2

type Record struct {
	ID       string `json:"ID"`
	Previous string `json:"previous"`
	Future   string `json:"future"`
	Data     string `json:"data"`
}

type RecordList struct {
	Records []Record
}

type FutureRecord struct {
	ID       string `json:"ID"`
	Previous string `json:"previous"`
	Future   string `json:"future"`
	Data     string `json:"data"`
}

func RecordToFutureRecord(record Record) FutureRecord {
	// var futureRecord FutureRecord
	futureRecord := FutureRecord{
		ID:       record.ID,
		Previous: record.Previous,
		Future:   "",
		Data:     record.Data,
	}
	return futureRecord
}

func PrintRecordList(list []*Record) {
	for i := 0; i < len(list); i++ {
		fmt.Printf("{\nID: %s,\nPrevious:%s,\nData:%s\n} \n", list[i].ID, list[i].Previous, list[i].Data)
	}
}
func PrintFutureRecordList(list []*FutureRecord) {
	for i := 0; i < len(list); i++ {
		fmt.Printf("{\nID: %s,\nPrevious:%s,\nFuture:%s,\nData:%s\n} \n", list[i].ID, list[i].Previous, list[i].Future, list[i].Data)
		// fmt.Printf("{\nID: %s,\nPrevious:%s,\nData:%s\n} \n", list[i].ID, list[i].Previous, list[i].Future, list[i].Data)
	}
}

func Float32ToByte(float float32) []byte {
	bits := math.Float32bits(float)
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, bits)

	return bytes
}

func IntToBytes(n int) []byte {
	data := int64(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func GenerateRecord(seed *rand.Rand, seq int) *Record {

	sha := sha256.New()
	sha.Write(IntToBytes(seq))
	// fmt.Println(hex.EncodeToString(sha.Sum(nil)))
	record := Record{
		ID:       hex.EncodeToString(sha.Sum(nil)),
		Previous: "",
		Future:   "",
		Data:     fmt.Sprint(seq),
	}
	return &record
}

func RollDice(seed *rand.Rand, max int) int {
	return seed.Intn(max)
}
func RollDiceWithoutSeed(max int) int {
	return rand.Intn(max)
}

func GetRandomTree(recordNum int) []*Record {

	var list []*Record

	rr := rand.New(rand.NewSource(time.Now().Unix()))
	// rr2 := rand.New(rand.NewSource(time.Now().Unix()))
	for i := 0; i < recordNum; i++ {
		newRecord := GenerateRecord(rr, i)
		if i != 0 {
			// previousNo := RollDice(rr2, i)
			previousNo := RollDiceWithoutSeed(i)
			println("Dice = ", previousNo)
			newRecord.Previous = list[previousNo].ID

			// parse the future part of previous record
			list[previousNo].Future += "|" + newRecord.ID
		}

		list = append(list, newRecord)
	}

	// naiveJson, err := json.Marshal(list)
	// if err != nil {
	// }
	// fmt.Println(string(naiveJson))
	return list
}

func GetRandomTreeWithJump(recordNum int, jump int) []*Record {

	var list []*Record

	var previousNo int

	rr := rand.New(rand.NewSource(time.Now().Unix()))
	// rr2 := rand.New(rand.NewSource(time.Now().Unix()))
	for i := 0; i < recordNum; i++ {
		recordInicator := recordNum*jump + i

		newRecord := GenerateRecord(rr, recordInicator)
		if i > 0 {
			// previousNo := RollDice(rr2, i)
			if jump < straightTreeNum {
				previousNo = i - 1
			} else {
				previousNo = RollDiceWithoutSeed(i)
			}

			newRecord.Previous = list[previousNo].ID

			// parse the future part of previous record
			list[previousNo].Future += "|" + newRecord.ID
		}

		list = append(list, newRecord)
	}

	return list
}

func GetMultipleRandomTrees(recordNum int, treeNum int) []*Record {

	var list []*Record
	var nodeListForEachTree [][]*Record
	var treeNodeIndicator []int

	for i := 0; i < treeNum; i++ {
		tree := GetRandomTreeWithJump(recordNum, i)
		nodeListForEachTree = append(nodeListForEachTree, tree)
		treeNodeIndicator = append(treeNodeIndicator, 0)
	}
	rr := rand.New(rand.NewSource(time.Now().Unix()))
	for i := 0; i < treeNum*recordNum; i++ {
		dice := rr.Intn(treeNum)
		for treeNodeIndicator[dice] >= recordNum {
			dice = (dice + 1) % treeNum
		}
		list = append(list, nodeListForEachTree[dice][treeNodeIndicator[dice]])
		treeNodeIndicator[dice]++
	}
	// naiveJson, err := json.Marshal(list)
	// if err != nil {
	// }
	// fmt.Println(string(naiveJson))
	return list
}

func GetForwardTestSequence() []int {
	var testSeq []int
	for i := straightTreeNum; i < testTreeNum; i++ {
		testSeq = append(testSeq, i*testNum)
	}
	return testSeq
}

func GetBackwardTestSequence() []int {
	var testSeq []int
	for i := 0; i < straightTreeNum; i++ {
		testSeq = append(testSeq, (i+1)*testNum-1)
	}
	return testSeq
}

func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//@brief:去除填充数据
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//@brief:AES加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//@brief:AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func TimeHold(round int) {
	var aeskey = []byte("12345678abcdefgh")
	fmt.Println("Timehold Start.")
	for i := 0; i < round; i++ {
		// pass := []byte(RollDiceWithoutSeed(1000))
		pass := IntToBytes(RollDiceWithoutSeed(1000))
		xpass, err := AesEncrypt(pass, aeskey)
		if err != nil {
			fmt.Println("what")
		}
		ciph := base64.StdEncoding.EncodeToString(xpass)
		sha := sha256.New()
		sha.Write([]byte(ciph))
		hex.EncodeToString(sha.Sum(nil))
	}
	fmt.Println("Timehold Done.")
}

type GraphRecord struct {
	FP   string `json:"FP"`
	BP   string `json:"BP"`
	Data string `json:"Data"`
}

func readRecordFile() string {
	b, err := ioutil.ReadFile("./graph_sample.json")
	if err != nil {
		fmt.Print(err)
	}
	str := string(b)
	return str
}

func deserializeJson(recordJson string) []GraphRecord {
	jsonAsBytes := []byte(recordJson)
	records := make([]GraphRecord, 0)
	err := json.Unmarshal(jsonAsBytes, &records)
	// fmt.Printf("%#v", records)
	if err != nil {
		panic(err)
	}
	return records
}

func main() {
	// treeNum := 10
	// recordNumInTree := 10
	// recordList := GetRandomListForAllTrees(treeNum, recordNumInTree)
	// q, err := json.Marshal(recordList)
	// if err != nil {
	// }
	// list := GetMultipleRandomTrees(testNum, testTreeNum)
	// naiveJson, err := json.Marshal(list)
	// if err != nil {
	// }
	// fmt.Println(string(naiveJson))
	// fmt.Println(GetForwardTestSequence())
	// fmt.Println(GetBackwardTestSequence())
	// TimeHold(10)
	recordList := readRecordFile()
	unmarshalledRecords := deserializeJson(recordList)
	for _, recordObj := range unmarshalledRecords {
		fmt.Printf("FP: %s, BP: %s \n", recordObj.FP, recordObj.BP)
	}
}
