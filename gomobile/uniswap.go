package gomobile

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/consensus/signatureschemes/bridgesig"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func quote0x(
	quote0xUrl string,
) (map[string]interface{}, error) {
	var (
		err       error
		resp      *http.Response
		bodyBytes []byte
		result    interface{}
	)
	if resp, err = http.Get(quote0xUrl); err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Request returns with fucking error!!!")
	}
	if bodyBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, err
	}
	return result.(map[string]interface{}), nil
}

func randomizeTimestamp() string {
	randomTime := rand.Int63n(time.Now().Unix()-94608000) + 94608000
	randomNow := time.Unix(randomTime, 0)
	return randomNow.String()
}

func rawsha3(b []byte) []byte {
	hashF := sha3.NewLegacyKeccak256()
	hashF.Write(b)
	buf := hashF.Sum(nil)
	return buf
}

func handleError(msg string) error {
	println(msg)
	return errors.New(msg)
}

func Sign0x(args string) (string, error) {
	// parse meta data
	bytes := []byte(args)
	println("Bytes: %v\n", bytes)

	paramMaps := make(map[string]interface{})

	err := json.Unmarshal(bytes, &paramMaps)
	if err != nil {
		println("Error can not unmarshal data : %v\n", err)
		return "", err
	}

	println("paramMaps:", paramMaps)

	data, ok := paramMaps["data"].(map[string]interface{})
	if !ok {
		return "", handleError("Invalid meta data param")
	}

	sourceToken, ok := data["sourceToken"].(string)
	if !ok {
		return "", handleError("Invalid source token")
	}

	destTokenSymbol, ok := data["destToken"].(string)
	if !ok {
		return "", handleError("Invalid dest token")
	}

	sourceQuantity, ok := data["sourceQuantity"].(string)
	if !ok {
		return "", handleError("Invalid source quantity")
	}

	tradeABI, ok := data["tradeABI"].(string)
	if !ok {
		return "", handleError("Invalid trade abi")
	}

	tradeDeployedAddress, ok := data["tradeDeployedAddress"].(string)
	if !ok {
		return "", handleError("Invalid deploy address")
	}

	privateKey, ok := data["privateKey"].(string)
	if !ok {
		return "", handleError("Invalid private key")
	}

	quoteData, ok := data["quoteData"].(string)
	if !ok {
		return "", handleError("Invalid private key")
	}

	quoteTo, ok := data["quoteTo"].(string)
	if !ok {
		return "", handleError("Invalid private key")
	}

	tradeAbi, _ := abi.JSON(strings.NewReader(tradeABI))

	forwarder := common.HexToAddress(quoteTo)
	dt := common.Hex2Bytes(quoteData[2:])
	tradeDeployAddr := common.HexToAddress(tradeDeployedAddress)

	srcToken := common.HexToAddress(sourceToken)
	destToken := common.HexToAddress(destTokenSymbol)

	srcQty := new(big.Int)
	srcQty, ok = srcQty.SetString(sourceQuantity, 10)
	if !ok {
		println("SetString: error")
	}

	input, err := tradeAbi.Pack("trade", srcToken, srcQty, destToken, dt, forwarder)

	println("INPUT")
	println(input)

	if err != nil {
		println(err)
		return "", handleError("Pack abi error")
	}

	timestamp := randomizeTimestamp()
	timestampBytes := []byte(timestamp)
	tempData := append(tradeDeployAddr[:], input...)
	tempData1 := append(tempData, timestampBytes...)

	signData := rawsha3(tempData1)

	scPrivateKey, _ := generateSmartContractInfo(privateKey)

	signBytes, _ := crypto.Sign(signData, &scPrivateKey)

	d := map[string]string{
		"signBytes": hex.EncodeToString(signBytes),
		"timestamp": hex.EncodeToString(timestampBytes),
		"input": hex.EncodeToString(input),
	}

	jsonString, err := json.Marshal(d)
	if err != nil {
		return "", handleError("Convert map to json string error")
	}

	return string(jsonString), nil
}

func SignKyber(args string) (string, error) {
	// parse meta data
	bytes := []byte(args)
	println("Bytes: %v\n", bytes)

	paramMaps := make(map[string]interface{})

	err := json.Unmarshal(bytes, &paramMaps)
	if err != nil {
		println("Error can not unmarshal data : %v\n", err)
		return "", err
	}

	println("paramMaps:", paramMaps)


	data, ok := paramMaps["data"].(map[string]interface{})
	if !ok {
		return "", handleError("Invalid meta data param")
	}

	sourceToken, ok := data["sourceToken"].(string)
	if !ok {
		return "", handleError("Invalid source token")
	}

	destTokenAddress, ok := data["destToken"].(string)
	if !ok {
		return "", handleError("Invalid dest token")
	}

	sourceQuantity, ok := data["sourceQuantity"].(string)
	if !ok {
		return "", handleError("Invalid source quantity")
	}

	tradeABI, ok := data["tradeABI"].(string)
	if !ok {
		return "", handleError("Invalid trade abi")
	}

	tradeDeployedAddress, ok := data["tradeDeployedAddress"].(string)
	if !ok {
		return "", handleError("Invalid deploy address")
	}

	privateKey, ok := data["privateKey"].(string)
	if !ok {
		return "", handleError("Invalid private key")
	}

	expectRateString, ok := data["expectRate"].(string)
	if !ok {
		return "", handleError("Invalid private key")
	}

	// Hardcode
	tradeAbi, _ := abi.JSON(strings.NewReader(tradeABI))

	tradeDeployAddr := common.HexToAddress(tradeDeployedAddress)

	srcToken := common.HexToAddress(sourceToken)
	destToken := common.HexToAddress(destTokenAddress)

	srcQty, ok := new(big.Int).SetString(sourceQuantity, 10)
	if !ok {
		println("SetString: error")
	}

	expectRate, ok := new(big.Int).SetString(expectRateString, 10)
	if !ok {
		println("SetString: error")
	}

	input, err := tradeAbi.Pack("trade", srcToken, srcQty, destToken, expectRate)
	if err != nil {
		println(err)
		return "", handleError("Pack abi error")
	}

	timestamp := randomizeTimestamp()
	timestampBytes := []byte(timestamp)
	tempData := append(tradeDeployAddr[:], input...)
	tempData1 := append(tempData, timestampBytes...)

	signData := rawsha3(tempData1)

	scPrivateKey, _ := generateSmartContractInfo(privateKey)

	signBytes, _ := crypto.Sign(signData, &scPrivateKey)

	d := map[string]string{
		"signBytes": hex.EncodeToString(signBytes),
		"timestamp": hex.EncodeToString(timestampBytes),
		"input": hex.EncodeToString(input),
	}

	jsonString, err := json.Marshal(d)
	if err != nil {
		return "", handleError("Convert map to json string error")
	}

	return string(jsonString), nil
}

func generateSmartContractInfo(privateKey string) (ecdsa.PrivateKey, ecdsa.PublicKey) {
	incPriKeyBytes, _, _ := base58.Base58Check{}.Decode(privateKey)
	scPrivateKey, scPublicKey := bridgesig.KeyGen(incPriKeyBytes)

	return scPrivateKey, scPublicKey
}

func GenerateContractAddress(args string) (string, error) {
	// parse meta data
	bytes := []byte(args)
	println("Bytes: %v\n", bytes)

	paramMaps := make(map[string]interface{})

	err := json.Unmarshal(bytes, &paramMaps)
	if err != nil {
		println("Error can not unmarshal data : %v\n", err)
		return "", err
	}

	println("paramMaps:", paramMaps)

	privateKey, ok := paramMaps["privateKey"].(string)
	if !ok {
		return "", errors.New("Invalid private key")
	}

	_, GeneratedPubKeyForSC := generateSmartContractInfo(privateKey)
	address := crypto.PubkeyToAddress(GeneratedPubKeyForSC).Hex()

	return address, nil
}

func WithdrawSmartContractBalance(args string) (string, error) {
	// parse meta data
	bytes := []byte(args)
	println("Bytes: %v\n", bytes)

	paramMaps := make(map[string]interface{})

	err := json.Unmarshal(bytes, &paramMaps)
	if err != nil {
		println("Error can not unmarshal data : %v\n", err)
		return "", err
	}

	println("paramMaps:", paramMaps)

	data, ok := paramMaps["data"].(map[string]interface{})
	if !ok {
		return "", handleError("Invalid meta data param")
	}

	tokenAddress, ok := data["tokenAddress"].(string)
	if !ok {
		return "", handleError("Invalid token address")
	}

	incognitoWalletAddress, ok := data["incognitoWalletAddress"].(string)
	if !ok {
		return "", handleError("Invalid wallet address")
	}

	privateKey, ok := data["privateKey"].(string)
	if !ok {
		return "", handleError("Invalid private key")
	}

	token := common.HexToAddress(tokenAddress)
	timestamp := []byte(randomizeTimestamp())
	tempData := append([]byte(incognitoWalletAddress), token[:]...)
	tempData1 := append(tempData, timestamp...)
	signData := rawsha3(tempData1)
	scPrivateKey, _ := generateSmartContractInfo(privateKey)

	signBytes, _ := crypto.Sign(signData, &scPrivateKey)

	d := map[string]string{
		"signBytes": hex.EncodeToString(signBytes),
		"timestamp": hex.EncodeToString(timestamp),
	}

	jsonString, err := json.Marshal(d)
	if err != nil {
		return "", handleError("Convert map to json string error")
	}

	return string(jsonString), nil
}

func main() {
	data := "{\"data\":{\"sourceToken\":\"0x0000000000000000000000000000000000000000\",\"sourceQuantity\":\"10000000000000000\",\"destToken\":\"0x9f8cfb61d3b2af62864408dd703f9c3beb55dff7\",\"quoteUrl\":\"https://kovan.api.0x.org/swap/v0/quote?sellToken=SAI&buyToken=ETH&sellAmount=100000000000000000\",\"tradeABI\":\"[{\\\"inputs\\\":[{\\\"internalType\\\":\\\"address\\\",\\\"name\\\":\\\"_wETH\\\",\\\"type\\\":\\\"address\\\"},{\\\"internalType\\\":\\\"address\\\",\\\"name\\\":\\\"_zeroProxy\\\",\\\"type\\\":\\\"address\\\"},{\\\"internalType\\\":\\\"addresspayable\\\",\\\"name\\\":\\\"_incognitoSmartContract\\\",\\\"type\\\":\\\"address\\\"}],\\\"payable\\\":false,\\\"stateMutability\\\":\\\"nonpayable\\\",\\\"type\\\":\\\"constructor\\\"},{\\\"payable\\\":true,\\\"stateMutability\\\":\\\"payable\\\",\\\"type\\\":\\\"fallback\\\"},{\\\"constant\\\":true,\\\"inputs\\\":[],\\\"name\\\":\\\"ETH_CONTRACT_ADDRESS\\\",\\\"outputs\\\":[{\\\"internalType\\\":\\\"contractIERC20\\\",\\\"name\\\":\\\"\\\",\\\"type\\\":\\\"address\\\"}],\\\"payable\\\":false,\\\"stateMutability\\\":\\\"view\\\",\\\"type\\\":\\\"function\\\"},{\\\"constant\\\":true,\\\"inputs\\\":[],\\\"name\\\":\\\"incognitoSmartContract\\\",\\\"outputs\\\":[{\\\"internalType\\\":\\\"addresspayable\\\",\\\"name\\\":\\\"\\\",\\\"type\\\":\\\"address\\\"}],\\\"payable\\\":false,\\\"stateMutability\\\":\\\"view\\\",\\\"type\\\":\\\"function\\\"},{\\\"constant\\\":false,\\\"inputs\\\":[{\\\"internalType\\\":\\\"contractIERC20\\\",\\\"name\\\":\\\"srcToken\\\",\\\"type\\\":\\\"address\\\"},{\\\"internalType\\\":\\\"uint256\\\",\\\"name\\\":\\\"amount\\\",\\\"type\\\":\\\"uint256\\\"},{\\\"internalType\\\":\\\"contractIERC20\\\",\\\"name\\\":\\\"destToken\\\",\\\"type\\\":\\\"address\\\"},{\\\"internalType\\\":\\\"bytes\\\",\\\"name\\\":\\\"callDataHex\\\",\\\"type\\\":\\\"bytes\\\"},{\\\"internalType\\\":\\\"address\\\",\\\"name\\\":\\\"_forwarder\\\",\\\"type\\\":\\\"address\\\"}],\\\"name\\\":\\\"trade\\\",\\\"outputs\\\":[{\\\"internalType\\\":\\\"address\\\",\\\"name\\\":\\\"\\\",\\\"type\\\":\\\"address\\\"},{\\\"internalType\\\":\\\"uint256\\\",\\\"name\\\":\\\"\\\",\\\"type\\\":\\\"uint256\\\"}],\\\"payable\\\":true,\\\"stateMutability\\\":\\\"payable\\\",\\\"type\\\":\\\"function\\\"},{\\\"constant\\\":false,\\\"inputs\\\":[{\\\"internalType\\\":\\\"uint256\\\",\\\"name\\\":\\\"amount\\\",\\\"type\\\":\\\"uint256\\\"}],\\\"name\\\":\\\"withdrawWrapETH\\\",\\\"outputs\\\":[],\\\"payable\\\":false,\\\"stateMutability\\\":\\\"nonpayable\\\",\\\"type\\\":\\\"function\\\"}]\",\"tradeDeployedAddress\":\"0x8d72EB3fcb1A97E24F0dC27f58AaeFad2383dD03\",\"privateKey\":\"112t8rowxJaMRUQGF3v1WbdjWiRyyb3LyDyhwptatBi1wAQt9XdofMGNRcLGSecioGJyJmajy6UUrJy6XV2tkvZuFx55ted263nTav7b28s6\"}}"
	result, err := Sign0x(data)

	println(result)
	println(err)
}

