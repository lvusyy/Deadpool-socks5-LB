package utils

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 从quake获取，结果为IP:PORT
func GetSocksFromQuake(quake QUAKEConfig) {
	defer Wg.Done()
	if quake.Switch != "open" {
		fmt.Println("---未开启quake---")
		return
	}
	fmt.Printf("***已开启quake,将根据配置条件从quake中获取%d条数据，然后进行有效性检测***\n", quake.ResultSize)
	jsonCondition := "{\"query\": \"" + strings.Replace(quake.QueryString, `"`, `\"`, -1) + "\",\"latest\":\"True\",\"start\": 0,\"size\": " + strconv.Itoa(quake.ResultSize) + ",\"include\":[\"ip\",\"port\"]}"
	headers := map[string]string{
		"X-QuakeToken": quake.Key,
		"Content-Type": "application/json"}
	content, err := fetchContent(quake.APIURL, "POST", 60, nil, headers, jsonCondition)
	if err != nil {
		fmt.Println("quake异常", err)
		return
	}
	var data map[string]interface{}
	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		fmt.Println("解析quake响应失败:", err)
		return
	}

	// 使用 0.0 进行比较，并安全检查字段是否存在和类型是否正确
	codeVal, okCode := data["code"]
	if !okCode {
		fmt.Println("QUAKE: 响应中缺少 'code' 字段")
		return
	}
	codeFloat, okCodeFloat := codeVal.(float64)
	if !okCodeFloat || codeFloat != 0.0 {
		message := "未知错误"
		if msgVal, okMsg := data["message"]; okMsg {
			if msgStr, okMsgStr := msgVal.(string); okMsgStr {
				message = msgStr
			}
		}
		fmt.Println("QUAKE:", message)
		return
	}

	dataVal, okData := data["data"]
	if !okData {
		fmt.Println("QUAKE: 响应中缺少 'data' 字段")
		return
	}
	arr, okArr := dataVal.([]interface{})
	if !okArr {
		fmt.Println("QUAKE: 'data' 字段不是预期的数组类型")
		return
	}

	fmt.Println("+++quake数据已取+++")
	addedCount := 0
	for _, item := range arr {
		itemMap, okMap := item.(map[string]interface{})
		if !okMap {
			fmt.Println("QUAKE: data 数组中的元素不是 map 类型")
			continue // 跳过这个无效元素
		}
		ipVal, okIp := itemMap["ip"]
		portVal, okPort := itemMap["port"]
		if !okIp || !okPort {
			fmt.Println("QUAKE: data 元素中缺少 'ip' 或 'port' 字段")
			continue // 跳过这个无效元素
		}
		ip, okIpStr := ipVal.(string)
		port, okPortFloat := portVal.(float64)
		if !okIpStr || !okPortFloat {
			fmt.Println("QUAKE: 'ip' 或 'port' 字段类型不正确")
			continue // 跳过这个无效元素
		}
		addSocks(ip + ":" + strconv.FormatFloat(port, 'f', -1, 64))
		addedCount++
	}
	fmt.Printf("---quake成功添加 %d 条代理---\n", addedCount)
}

// 从FOFA获取,结果为IP:PORT
func GetSocksFromFofa(fofa FOFAConfig) {
	defer Wg.Done()
	if fofa.Switch != "open" {
		fmt.Println("---未开启fofa---")
		return
	}
	fmt.Printf("***已开启fofa,将根据配置条件从fofa中获取%d条数据，然后进行有效性检测***\n", fofa.ResultSize)

	params := map[string]string{
		"email":   fofa.Email,
		"key":     fofa.Key,
		"fields":  "ip,port",
		"qbase64": base64.URLEncoding.EncodeToString([]byte(fofa.QueryString)),
		"size":    strconv.Itoa(fofa.ResultSize)}
	content, err := fetchContent(fofa.APIURL, "GET", 60, params, nil, "")
	if err != nil {
		fmt.Println("访问fofa异常", err)
		return
	}
	var data map[string]interface{}
	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		fmt.Println("解析fofa响应失败:", err)
		return
	}

	// 安全检查 error 和 errmsg 字段
	errorVal, okError := data["error"]
	if okError {
		if errorBool, okErrorBool := errorVal.(bool); okErrorBool && errorBool {
			message := "未知错误"
			if errMsgVal, okErrMsg := data["errmsg"]; okErrMsg {
				if errMsgStr, okErrMsgStr := errMsgVal.(string); okErrMsgStr {
					message = errMsgStr
				}
			}
			fmt.Println("FOFA:", message)
			return
		}
	}

	resultsVal, okResults := data["results"]
	if !okResults {
		fmt.Println("FOFA: 响应中缺少 'results' 字段")
		return
	}
	array, okArray := resultsVal.([]interface{})
	if !okArray {
		fmt.Println("FOFA: 'results' 字段不是预期的数组类型")
		return
	}

	fmt.Println("+++fofa数据已取+++")
	addedCount := 0
	for _, itemArray := range array {
		itemSlice, okSlice := itemArray.([]interface{})
		if !okSlice || len(itemSlice) < 2 {
			fmt.Println("FOFA: results 数组中的元素不是切片或长度不足")
			continue // 跳过这个无效元素
		}
		ipVal, okIp := itemSlice[0].(string)
		portVal, okPort := itemSlice[1].(string)
		if !okIp || !okPort {
			fmt.Println("FOFA: results 元素中的 IP 或 Port 不是字符串类型")
			continue // 跳过这个无效元素
		}
		addSocks(ipVal + ":" + portVal)
		addedCount++
	}
	fmt.Printf("---fofa成功添加 %d 条代理---\n", addedCount)

}

// 从鹰图获取，结果为IP:PORT
func GetSocksFromHunter(hunter HUNTERConfig) {
	defer Wg.Done()
	if hunter.Switch != "open" {
		fmt.Println("---未开启hunter---")
		return
	}
	fmt.Printf("***已开启hunter,将根据配置条件从hunter中获取%d条数据,然后进行有效性检测***\n", hunter.ResultSize)

	var exeData int //记录处理了几条
	end := hunter.ResultSize / 100
	for i := 1; i <= end; i++ {
		params := map[string]string{
			"api-key":   hunter.Key,
			"search":    base64.URLEncoding.EncodeToString([]byte(hunter.QueryString)),
			"page":      strconv.Itoa(i),
			"page_size": "100"}
		fmt.Printf("HUNTER:每页100条,正在查询第%v页\n", i)
		content, err := fetchContent(hunter.APIURL, "GET", 60, params, nil, "")
		if err != nil {
			fmt.Println("访问hunter异常", err)
			return
		}
		var data map[string]interface{}
		err = json.Unmarshal([]byte(content), &data)
		if err != nil {
			fmt.Printf("HUNTER: 解析第 %v 页响应失败: %v\n", i, err)
			continue // 尝试下一页
		}

		// 安全检查 code 和 message 字段
		codeVal, okCode := data["code"]
		if !okCode {
			fmt.Printf("HUNTER: 第 %v 页响应中缺少 'code' 字段\n", i)
			continue
		}
		codeFloat, okCodeFloat := codeVal.(float64)
		// 使用 200.0 进行比较
		if !okCodeFloat || codeFloat != 200.0 {
			message := "未知错误"
			if msgVal, okMsg := data["message"]; okMsg {
				if msgStr, okMsgStr := msgVal.(string); okMsgStr {
					message = msgStr
				}
			}
			fmt.Printf("HUNTER: 第 %v 页错误: %s\n", i, message)
			// 如果是认证失败等严重错误，可能需要 break
			// if codeFloat == 401.0 { break }
			continue // 否则尝试下一页
		}

		dataVal, okData := data["data"]
		if !okData {
			fmt.Printf("HUNTER: 第 %v 页响应中缺少 'data' 字段\n", i)
			continue
		}
		rsData, okRsData := dataVal.(map[string]interface{})
		if !okRsData {
			fmt.Printf("HUNTER: 第 %v 页 'data' 字段不是预期的 map 类型\n", i)
			continue
		}

		totalVal, okTotal := rsData["total"]
		if !okTotal {
			fmt.Printf("HUNTER: 第 %v 页 'data' 中缺少 'total' 字段\n", i)
			continue
		}
		total, okTotalFloat := totalVal.(float64)
		if !okTotalFloat {
			fmt.Printf("HUNTER: 第 %v 页 'total' 字段不是数字类型\n", i)
			continue
		}

		if total == 0 {
			fmt.Println("HUNTER:xxx根据配置语法,未取到数据xxx")
			break // 没有数据了，退出循环
		}

		arrVal, okArr := rsData["arr"]
		if !okArr {
			fmt.Printf("HUNTER: 第 %v 页 'data' 中缺少 'arr' 字段\n", i)
			continue
		}
		arr, okArrSlice := arrVal.([]interface{})
		if !okArrSlice {
			fmt.Printf("HUNTER: 第 %v 页 'arr' 字段不是预期的数组类型\n", i)
			continue
		}

		pageAddedCount := 0
		for _, item := range arr {
			itemMap, okMap := item.(map[string]interface{})
			if !okMap {
				fmt.Printf("HUNTER: 第 %v 页 arr 元素不是 map 类型\n", i)
				continue
			}
			ipVal, okIp := itemMap["ip"]
			portVal, okPort := itemMap["port"]
			if !okIp || !okPort {
				fmt.Printf("HUNTER: 第 %v 页 arr 元素缺少 'ip' 或 'port'\n", i)
				continue
			}
			ip, okIpStr := ipVal.(string)
			port, okPortFloat := portVal.(float64)
			if !okIpStr || !okPortFloat {
				fmt.Printf("HUNTER: 第 %v 页 'ip' 或 'port' 类型不正确\n", i)
				continue
			}
			addSocks(ip + ":" + strconv.FormatFloat(port, 'f', -1, 64))
			exeData++ // 总处理数增加
			pageAddedCount++
		}
		fmt.Printf("---hunter 第 %d 页成功添加 %d 条代理---\n", i, pageAddedCount)
		if float64(exeData) >= total {
			break
		}
		if end > 1 && i != end {
			time.Sleep(3 * time.Second) //防止hunter提示访问过快获取不到结果
		}
	}
	fmt.Println("+++hunter数据已取+++")
}

// 从本地文件获取，格式为IP:PORT
func GetSocksFromFile(socksFileName string) {
	_, err := os.Stat(socksFileName)
	if !os.IsNotExist(err) {
		fmt.Println("***当前目录下存在" + socksFileName + ",将按行读取格式为IP:PORT的socks5代理***")
		file, err := os.Open(socksFileName)
		if err != nil {
			fmt.Println("读取文件"+socksFileName+"异常，略过该文件中的代理，异常信息为:", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) != "" {
				SocksList = append(SocksList, line)
			}
		}
		// 检查扫描过程中是否发生了错误
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file,请确认文件中的socks5代理是IP:PORT格式:", err)
		}
	} else {
		fmt.Println(socksFileName + "文件不存在，将根据配置信息从网络空间测绘平台取socks5的代理")
	}
}
