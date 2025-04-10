package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// addSocks 使用导出的 AddSocksMu 进行同步
func addSocks(socks5 string) {
	AddSocksMu.Lock() // 使用导出的 AddSocksMu
	SocksList = append(SocksList, socks5)
	AddSocksMu.Unlock() // 使用导出的 AddSocksMu
}
func fetchContent(baseURL string, method string, timeout int, urlParams map[string]string, headers map[string]string, jsonBody string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(timeout) * time.Second,
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if urlParams != nil {
		q := u.Query()
		for key, value := range urlParams {
			q.Set(key, value)
		}
		u.RawQuery = q.Encode()
	}

	var req *http.Request
	if jsonBody != "" {
		req, err = http.NewRequest(method, u.String(), bytes.NewBufferString(jsonBody))
	} else {
		req, err = http.NewRequest(method, u.String(), nil)
	}

	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
	if len(headers) != 0 {
		for key, value := range headers {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func RemoveDuplicates(list *[]string) {
	AddSocksMu.Lock()         // 使用导出的 AddSocksMu
	defer AddSocksMu.Unlock() // 使用导出的 AddSocksMu
	seen := make(map[string]struct{})
	var result []string
	for _, sock := range *list {
		if _, ok := seen[sock]; !ok {
			result = append(result, sock)
			seen[sock] = struct{}{}
		}
	}

	*list = result
}

func CheckSocks(checkSocks CheckSocksConfig, socksListParam []string) {
	startTime := time.Now()
	maxConcurrentReq := checkSocks.MaxConcurrentReq
	timeout := checkSocks.Timeout
	semaphore = make(chan struct{}, maxConcurrentReq)

	checkRspKeywords := checkSocks.CheckRspKeywords
	checkGeolocateConfig := checkSocks.CheckGeolocate
	checkGeolocateSwitch := checkGeolocateConfig.Switch
	isOpenGeolocateSwitch := false
	reqUrl := checkSocks.CheckURL
	if checkGeolocateSwitch == "open" {
		isOpenGeolocateSwitch = true
		reqUrl = checkGeolocateConfig.CheckURL
	}
	fmt.Printf("时间:[ %v ] 并发:[ %v ],超时标准:[ %vs ]\n", time.Now().Format("2006-01-02 15:04:05"), maxConcurrentReq, timeout)
	var num int
	total := len(socksListParam)
	var tmpEffectiveList []string
	var tmpMu sync.Mutex
	for _, proxyAddr := range socksListParam {

		Wg.Add(1)
		semaphore <- struct{}{}
		go func(proxyAddr string) {
			tmpMu.Lock()
			num++
			fmt.Printf("\r正检测第 [ %v/%v ] 个代理,异步处理中...                    ", num, total)
			tmpMu.Unlock()
			defer Wg.Done()
			defer func() {
				<-semaphore

			}()
			socksProxy := "socks5://" + proxyAddr
			proxy := func(_ *http.Request) (*url.URL, error) {
				return url.Parse(socksProxy)
			}
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           proxy,
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(timeout) * time.Second,
			}
			req, err := http.NewRequest("GET", reqUrl, nil)
			if err != nil {
				// 添加错误日志
				fmt.Printf("\nError creating request for %s: %v\n", proxyAddr, err)
				return
			}
			req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
			req.Header.Add("referer", "https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&tn=baidu&wd=ip&fenlei=256&rsv_pq=0xc23dafcc00076e78&rsv_t=6743gNBuwGYWrgBnSC7Yl62e52x3CKQWYiI10NeKs73cFjFpwmqJH%2FOI%2FSRG&rqlang=en&rsv_dl=tb&rsv_enter=1&rsv_sug3=5&rsv_sug1=5&rsv_sug7=101&rsv_sug2=0&rsv_btype=i&prefixsug=ip&rsp=4&inputT=2165&rsv_sug4=2719")
			resp, err := client.Do(req)
			if err != nil {
				// fmt.Printf("%v: %v\n", proxyAddr, err)
				// fmt.Printf("+++++++代理不可用：%v+++++++\n", proxyAddr)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				// 添加错误日志
				fmt.Printf("\nError reading response body for %s: %v\n", proxyAddr, err)
				return
			}
			stringBody := string(body)
			if !isOpenGeolocateSwitch {
				if !strings.Contains(stringBody, checkRspKeywords) {
					return
				}
			} else {
				//直接循环要排除的关键字，任一命中就返回
				for _, keyword := range checkGeolocateConfig.ExcludeKeywords {
					if strings.Contains(stringBody, keyword) {
						// fmt.Println("忽略：" + proxyAddr + "包含：" + keyword.(string))
						return
					}
				}
				//直接循环要必须包含的关键字，任一未命中就返回
				for _, keyword := range checkGeolocateConfig.IncludeKeywords {
					if !strings.Contains(stringBody, keyword) {
						// fmt.Println("忽略：" + proxyAddr + "未包含：" + keyword.(string))
						return
					}
				}

			}
			tmpMu.Lock()
			tmpEffectiveList = append(tmpEffectiveList, proxyAddr)
			tmpMu.Unlock()
		}(proxyAddr)
	}
	Wg.Wait()
	Mu.Lock() // 使用导出的 Mu
	EffectiveList = make([]string, len(tmpEffectiveList))
	copy(EffectiveList, tmpEffectiveList)
	proxyIndex = 0
	Mu.Unlock() // 使用导出的 Mu
	sec := int(time.Since(startTime).Seconds())
	if sec == 0 {
		sec = 1
	}
	fmt.Printf("\n根据配置规则检测完成,用时 [ %vs ] ,共发现 [ %v ] 个可用\n", sec, len(tmpEffectiveList))
}

func WriteLinesToFile() error {
	Mu.Lock() // 使用导出的 Mu
	// defer mu.Unlock() // 移除 defer，将在复制后显式解锁
	file, err := os.Create(LastDataFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	// 复制一份 EffectiveList 以避免长时间持有锁
	listCopy := make([]string, len(EffectiveList))
	copy(listCopy, EffectiveList)
	// 释放锁，因为我们现在操作的是副本
	Mu.Unlock() // 使用导出的 Mu。复制完成后显式解锁

	// 使用副本进行写入
	for _, line := range listCopy {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func DefineDial(ctx context.Context, network, address string) (net.Conn, error) {

	return transmitReqFromClient(network, address)
}

// 改进 transmitReqFromClient 函数
func transmitReqFromClient(network string, address string) (net.Conn, error) {
	timeout := time.Duration(Timeout) * time.Second
	dialer := &net.Dialer{
		Timeout: timeout, // net.Dialer 的 Timeout 应用于建立到 SOCKS5 服务器的连接
	}

	Mu.Lock() // 使用导出的 Mu
	// initialIndex := proxyIndex // 移除未使用的变量
	listLen := len(EffectiveList)
	Mu.Unlock() // 使用导出的 Mu

	if listLen == 0 {
		return nil, fmt.Errorf("no available proxies in EffectiveList")
	}

	// 尝试最多 listLen 次代理
	for i := 0; i < listLen; i++ {
		Mu.Lock() // 使用导出的 Mu
		// 检查在循环过程中列表是否变空
		if len(EffectiveList) == 0 {
			Mu.Unlock() // 使用导出的 Mu
			return nil, fmt.Errorf("no available proxies left during attempts")
		}
		// 计算当前要使用的代理索引
		// 注意：这里需要小心处理并发删除导致 listLen 变化的情况
		currentListLen := len(EffectiveList)
		if currentListLen == 0 { // 再次检查，以防万一
			Mu.Unlock() // 使用导出的 Mu
			return nil, fmt.Errorf("no available proxies left during attempts (concurrent modification)")
		}
		// 使用 initialIndex 和 i 结合当前列表长度来计算索引，避免越界
		// (initialIndex + i) % currentListLen 似乎更健壮，但需要确保 initialIndex 仍然有效
		// 一个更简单的方法是直接使用当前的 proxyIndex，并在失败时让 delInvalidProxy 处理索引更新
		currentIndex := proxyIndex
		tempProxy := EffectiveList[currentIndex]
		// 在获取当前代理后，立即更新全局 proxyIndex 指向下一个，确保原子性
		proxyIndex = (currentIndex + 1) % currentListLen
		Mu.Unlock() // 使用导出的 Mu

		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "\t" + tempProxy)

		// 为 SOCKS5 拨号创建上下文，包含整体超时
		ctx, cancel := context.WithTimeout(context.Background(), timeout) // 整体超时

		// 使用 proxy.SOCKS5 创建拨号器
		socksDialer, err := proxy.SOCKS5(network, tempProxy, nil, dialer)
		if err != nil { // 创建拨号器失败
			cancel() // 取消上下文
			fmt.Printf("Error creating SOCKS5 dialer for %s: %v\n", tempProxy, err)
			// 创建拨号器失败通常不是代理本身的问题，不应删除代理
			// delInvalidProxy(tempProxy) // 移除调用
			continue // 直接尝试下一个代理
		}

		// 使用 ContextDialer 进行拨号
		contextDialer, ok := socksDialer.(proxy.ContextDialer)
		if !ok {
			cancel() // 取消上下文
			fmt.Printf("Warning: SOCKS5 dialer for %s does not support context.Context\n", tempProxy)
			// 回退到不带 context 的 Dial，依赖 dialer 内部的超时
			conn, err := socksDialer.Dial(network, address)
			if err == nil {
				// 连接成功 (no context)
				// proxyIndex 已在循环开始时更新，此处无需操作
				return conn, nil
			}
			// 连接失败
			fmt.Printf("%s 连接失败 (no context): %v\n", tempProxy, err)
			delInvalidProxy(tempProxy) // 从列表中移除无效代理
			continue                   // 尝试下一个代理
		}

		// 使用 ContextDialer 进行拨号，应用整体超时
		conn, err := contextDialer.DialContext(ctx, network, address)
		cancel() // 无论成功失败，都取消上下文

		if err == nil {
			// 连接成功 (context)
			// proxyIndex 已在循环开始时更新，此处无需操作
			return conn, nil
		}

		// 连接失败
		fmt.Printf("%s 连接失败: %v\n", tempProxy, err)
		delInvalidProxy(tempProxy) // 从列表中移除无效代理

		// 检查是否是超时错误
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Printf("%s 超时\n", tempProxy)
		} else if ctx.Err() == context.DeadlineExceeded {
			fmt.Printf("%s 整体超时\n", tempProxy)
		}
	}

	// 如果循环完成仍未成功连接
	return nil, fmt.Errorf("failed to connect through any available proxy after %d attempts", listLen)
}

// getNextProxy 函数已被 transmitReqFromClient 内部逻辑取代，移除
// 使用过程中删除无效的代理
func delInvalidProxy(proxy string) {
	Mu.Lock()         // 使用导出的 Mu
	defer Mu.Unlock() // 确保在函数退出时释放锁

	foundIndex := -1
	for i, p := range EffectiveList {
		if p == proxy {
			foundIndex = i
			break
		}
	}

	if foundIndex != -1 {
		// 从切片中移除元素
		EffectiveList = append(EffectiveList[:foundIndex], EffectiveList[foundIndex+1:]...)
		newLen := len(EffectiveList)

		// 如果列表为空，重置 proxyIndex
		if newLen == 0 {
			proxyIndex = 0
			return // 列表已空，无需进一步调整
		}

		// 调整 proxyIndex
		// 如果删除的元素在当前 proxyIndex 之前或就是当前 proxyIndex，
		// 并且 proxyIndex 不是 0（因为删除第一个元素后，索引 0 仍然有效），
		// 则需要将 proxyIndex 向前移动一位，以保持指向逻辑上的下一个元素。
		// 但是，transmitReqFromClient 在获取代理后立即递增了 proxyIndex，
		// 所以这里的调整逻辑变得复杂且容易出错。

		// 更简单和健壮的方法是：确保 proxyIndex 不会越界。
		// transmitReqFromClient 会在每次循环开始时根据当前长度计算索引，
		// 所以这里只需要保证 proxyIndex 在有效范围内即可。
		if proxyIndex >= newLen {
			proxyIndex = 0 // 如果越界，则重置为 0
		}
		// 注意：这种方法依赖 transmitReqFromClient 在循环开始时正确处理索引。
		// 如果 transmitReqFromClient 的逻辑是先获取 currentIndex = proxyIndex，
		// 然后 proxyIndex = (currentIndex + 1) % currentLen，那么这里的边界检查就足够了。
	}
}

func GetSocks(config Config) {
	GetSocksFromFile(LastDataFile)
	//从fofa获取
	Wg.Add(1)
	go GetSocksFromFofa(config.FOFA)
	//从hunter获取
	Wg.Add(1)
	go GetSocksFromHunter(config.HUNTER)
	//从quake中取
	Wg.Add(1)
	go GetSocksFromQuake(config.QUAKE)
	Wg.Wait()
	//根据IP:PORT去重，此步骤会存在同IP不同端口的情况，这种情况不再单独过滤，这种情况，最终的出口IP可能不一样
	RemoveDuplicates(&SocksList)
}
