package main

import (
	"Deadpool/utils"
	"context"
	"crypto/tls" // 添加导入
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http" // 添加导入
	"os"
	"strconv"
	"strings"
	"time" // 添加导入

	"github.com/armon/go-socks5"
	"github.com/robfig/cron/v3"
)

// 添加 HTTP 代理处理器
type httpProxyHandler struct {
	userName    string
	password    string
	proxyClient *http.Client // 添加一个 http.Client 字段
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 处理认证
	if h.userName != "" && h.password != "" {
		auth := r.Header.Get("Proxy-Authorization")
		if !h.checkAuth(auth) {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy Authentication Required\"")
			w.WriteHeader(407)
			return
		}
	}

	if r.Method == "CONNECT" {
		h.handleHTTPS(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

func (h *httpProxyHandler) checkAuth(auth string) bool {
	if auth == "" {
		return false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}
	return credentials[0] == h.userName && credentials[1] == h.password
}

func (h *httpProxyHandler) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// 使用 utils.DefineDial 通过 SOCKS5 代理池建立连接
	targetConn, err := utils.DefineDial(context.Background(), "tcp", r.Host)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// 发送连接成功响应
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// 创建双向数据转发
	go transfer(targetConn, clientConn)
	transfer(clientConn, targetConn)
}

// 重写 handleHTTP 函数
func (h *httpProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// 移除代理特定的头部信息
	r.RequestURI = "" // 清空 RequestURI，让 http.Client 处理
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")

	// 如果需要，设置 X-Forwarded-For
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// 如果已有 X-Forwarded-For，附加 IP
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		r.Header.Set("X-Forwarded-For", clientIP)
	}

	// 使用配置了 SOCKS5 代理池的 http.Client 发送请求
	// 直接使用 Transport.RoundTrip 更底层，避免 client 自动处理重定向等
	resp, err := h.proxyClient.Transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Error forwarding request: "+err.Error(), http.StatusBadGateway) // 使用 502 Bad Gateway 更合适
		// 考虑在这里也调用 delInvalidProxy，但这需要修改 DefineDial 或 RoundTrip 来返回使用的代理信息
		// 暂时不处理自动删除，因为 RoundTrip 错误不一定代表代理本身失效
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		// 如果在复制响应体时出错，记录日志可能比发送 HTTP 错误更好，因为头部已经发送
		log.Printf("Error copying response body: %v", err)
	}
}

func transfer(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func main() {
	utils.Banner()
	// fmt.Print("By:thinkoaa GitHub:https://github.com/thinkoaa/Deadpool\n\n\n")
	//读取配置文件
	config, err := utils.LoadConfig("config.toml")
	if err != nil {
		fmt.Printf("加载 config.toml 失败: %v\n", err)
		os.Exit(1)
	}

	//从本地文件中取socks代理
	fmt.Print("***直接使用fmt打印当前使用的代理,若高并发时,命令行打印可能会阻塞，不对打印做特殊处理，可忽略，不会影响实际的请求转发***\n\n")
	utils.GetSocks(config)
	if len(utils.SocksList) == 0 {
		fmt.Println("未发现代理数据,请调整配置信息,或向" + utils.LastDataFile + "中直接写入IP:PORT格式的socks5代理\n程序退出")
		os.Exit(1)
	}
	fmt.Printf("根据IP:PORT去重后，共发现%v个代理\n检测可用性中......\n", len(utils.SocksList))

	//开始检测代理存活性

	utils.Timeout = config.CheckSocks.Timeout
	utils.CheckSocks(config.CheckSocks, utils.SocksList)
	//根据配置，定时检测内存中的代理存活信息
	cron := cron.New()
	periodicChecking := strings.TrimSpace(config.Task.PeriodicChecking)
	cronFlag := false
	if periodicChecking != "" {
		cronFlag = true
		cron.AddFunc(periodicChecking, func() {
			fmt.Printf("\n===代理存活自检 开始===\n\n")
			// 加锁读取 EffectiveList
			utils.Mu.Lock()
			tempList := make([]string, len(utils.EffectiveList))
			copy(tempList, utils.EffectiveList)
			utils.Mu.Unlock()
			utils.CheckSocks(config.CheckSocks, tempList)
			fmt.Printf("\n===代理存活自检 结束===\n\n")
		})
	}
	//根据配置信息，周期性取本地以及hunter、quake、fofa的数据
	periodicGetSocks := strings.TrimSpace(config.Task.PeriodicGetSocks)
	if periodicGetSocks != "" {
		cronFlag = true
		cron.AddFunc(periodicGetSocks, func() {
			fmt.Printf("\n===周期性取代理数据 开始===\n\n")
			// 加锁清空 SocksList
			utils.AddSocksMu.Lock()
			utils.SocksList = utils.SocksList[:0]
			utils.AddSocksMu.Unlock()
			utils.GetSocks(config)
			// 加锁读取 SocksList 长度和内容以供 CheckSocks 使用
			utils.AddSocksMu.Lock()
			fmt.Printf("根据IP:PORT去重后，共发现%v个代理\n检测可用性中......\n", len(utils.SocksList))
			socksListCopy := make([]string, len(utils.SocksList))
			copy(socksListCopy, utils.SocksList)
			utils.AddSocksMu.Unlock()
			utils.CheckSocks(config.CheckSocks, socksListCopy) // 传递副本
			// 加锁检查 EffectiveList 长度
			utils.Mu.Lock()
			shouldWrite := len(utils.EffectiveList) != 0
			utils.Mu.Unlock()
			if shouldWrite {
				utils.WriteLinesToFile() //存活代理写入硬盘，以备下次启动直接读取
			}
			fmt.Printf("\n===周期性取代理数据 结束===\n\n")

		})
	}

	if cronFlag {
		cron.Start()
	}

	if len(utils.EffectiveList) == 0 {
		fmt.Println("根据规则检测后，未发现满足要求的代理,请调整配置,程序退出")
		os.Exit(1)
	}

	utils.WriteLinesToFile() //存活代理写入硬盘，以备下次启动直接读取

	// 创建一个配置了 SOCKS5 代理池的 http.Transport
	proxyTransport := &http.Transport{
		DialContext:       utils.DefineDial,                      // 使用 utils.DefineDial 作为 DialContext
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // 根据需要配置 TLS
		DisableKeepAlives: true,                                  // !!! 禁用 KeepAlive 以强制为每个请求新建连接，触发轮询 !!!
		// 可以根据需要设置其他 Transport 参数，例如 MaxIdleConns, IdleConnTimeout 等
		MaxIdleConnsPerHost:   -1, // 禁用连接池（配合 DisableKeepAlives）
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// 创建使用自定义 Transport 的 http.Client
	proxyClient := &http.Client{
		Transport: proxyTransport,
		Timeout:   time.Duration(utils.Timeout+10) * time.Second, // Client 的超时应略大于 Transport 的超时
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 禁止自动重定向，让客户端浏览器处理
			return http.ErrUseLastResponse
		},
	}

	// 开启监听
	// SOCKS5 服务器配置。Dial 必须为 nil 或标准拨号器，
	// 不能是 utils.DefineDial，否则会导致循环。
	conf := &socks5.Config{
		Dial:   utils.DefineDial, // 直接使用 utils.DefineDial，签名匹配
		Logger: log.New(io.Discard, "", log.LstdFlags),
	}
	userName := strings.TrimSpace(config.Listener.UserName)
	password := strings.TrimSpace(config.Listener.Password)
	if userName != "" && password != "" {
		// 使用从配置加载的 userName 和 password 变量
		// StaticCredentials 是 map[string]string，键是用户名，值是密码
		cator := socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{
			userName: password, // 使用变量 userName 作为键，变量 password 作为值
		}}
		conf.AuthMethods = []socks5.Authenticator{cator}
	}
	server, err := socks5.New(conf)
	if err != nil {
		fmt.Printf("创建 SOCKS5 服务器失败: %v\n", err)
		os.Exit(1)
	}
	listener := config.Listener.IP + ":" + strconv.Itoa(config.Listener.Port)
	fmt.Printf("======SOCKS5代理已启动在 socks5://%v ======\n", listener)
	// 启动 SOCKS5 代理服务器
	go func() {
		if err := server.ListenAndServe("tcp", listener); err != nil {
			fmt.Printf("SOCKS5代理启动失败：%v\n", err)
			os.Exit(1)
		}
	}()

	// 启动 HTTP 代理服务器
	httpListener := config.Listener.IP + ":" + strconv.Itoa(config.Listener.HttpPort) // 使用 HttpPort
	fmt.Printf("======HTTP代理已启动在 http://%v ======\n", httpListener)
	handler := &httpProxyHandler{
		userName:    userName,
		password:    password,
		proxyClient: proxyClient, // 将创建的 client 传递给 handler
	}
	if err := http.ListenAndServe(httpListener, handler); err != nil {
		fmt.Printf("HTTP代理启动失败：%v\n", err)
		os.Exit(1)
	}
}
