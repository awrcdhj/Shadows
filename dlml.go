#!desc=
[Service]
{
	&quot;//&quot;: &quot;tcp超时, 默认600秒&quot;,
	&quot;Tcp_timeout&quot;: 600,

	&quot;//&quot;: &quot;udp超时, 默认30秒&quot;,
	&quot;Udp_timeout&quot;: 30,

	&quot;//&quot;: &quot;http_tunnel监听地址, 可设置多个&quot;,
	&quot;listen_addr&quot;: [&quot;:8080&quot;,&quot;2222&quot;,&quot;443&quot;,&quot;80&quot;, &quot;:12224&quot;],

	&quot;//&quot;: &quot;设定请求头中获取host的key, 默认Host&quot;,
	&quot;proxy_key&quot;: &quot;Host&quot;,

	&quot;//&quot;: &quot;加密密码, 默认没有密码(普通http_tunnel代理)&quot;,
	&quot;encrypt_password&quot;: &quot;password&quot;,

	&quot;//&quot;: &quot;开启tcpDNS转udpDNS, 可稍微加快DNS解析速度, 默认关闭&quot;,
	&quot;Enable_dns_tcpOverUdp&quot;: true,

	&quot;//&quot;: &quot;开启httpDNS, httpDNS无需http_tunnel握手, 可稍微加快DNS解析速度, 默认关闭&quot;,
	&quot;Enable_httpDNS&quot;: true,

	&quot;//&quot;: &quot;开启tcpFastOpen, 可稍微加快创建连接速度(免流可能不适用), 默认关闭&quot;,
	&quot;Enable_TFO&quot;: false,

	&quot;//&quot;: &quot;以下是tls配置&quot;,
	&quot;Tls&quot;: {
		&quot;//&quot;: &quot;tls监听地址, 可设置多个&quot;,
		&quot;listen_addr&quot;: [&quot;127.0.0.1:6171&quot;, &quot;[::1]:1224&quot;, &quot;:9635&quot;],

		&quot;//&quot;: &quot;自动生成指定host的ssl/tls证书(如果留空则所有host都可以连接)&quot;,
		&quot;AutoCertHosts&quot;: [&quot;m.baidu.com&quot;, &quot;yaohuo.me&quot;, &quot;mymy.ip&quot;],

		&quot;//&quot;: &quot;手动指定cert和key文件, 两者必须同时存在&quot;,
		&quot;cert_file&quot;: &quot;Thor SSL CA 21-09-11 08_46.cer&quot;,
		&quot;key_file&quot;: &quot;Thor SSL CA 21-09-11 08_46.p12&quot;
	}
}
package master

import (
	&quot;bytes&quot;
	&quot;crypto/tls&quot;
	&quot;log&quot;
	&quot;net&quot;
	&quot;time&quot;
)

func isHttpHeader(header []byte) bool {
	if bytes.HasPrefix(header, []byte(&quot;CONNECT&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;GET&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;POST&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;HEAD&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;PUT&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;COPY&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;DELETE&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;MOVE&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;OPTIONS&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;LINK&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;UNLINK&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;TRACE&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;PATCH&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;WRAPPED&quot;)) == true {
		return true
	}
	return false
}

func rspHeader(header []byte) []byte {
	if bytes.Contains(header, []byte(&quot;WebSocket&quot;)) == true {
		return []byte(&quot;HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: CuteBi Network Tunnel, (%&gt;w&lt;%)\r\n\r\n&quot;)
	} else if bytes.HasPrefix(header, []byte(&quot;CON&quot;)) == true {
		return []byte(&quot;HTTP/1.1 200 Connection established\r\nServer: CuteBi Network Tunnel, (%&gt;w&lt;%)\r\nConnection: keep-alive\r\n\r\n&quot;)
	} else {
		return []byte(&quot;HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: CuteBi Network Tunnel, (%&gt;w&lt;%)\r\nConnection: keep-alive\r\n\r\n&quot;)
	}
}

func handleTunnel(cConn net.Conn, payload []byte, tlsConfig *tls.Config) {
	defer tcpBufferPool.Put(payload)

	cConn.SetReadDeadline(time.Now().Add(config.Tcp_timeout))
	RLen, err := cConn.Read(payload)
	if err != nil || RLen &lt;= 0 {
		cConn.Close()
		return
	}
	if isHttpHeader(payload[:RLen]) == false {
		/* 转为tls的conn */
		if tlsConfig != nil {
			cConn = tls.Server(cConn, tlsConfig)
		}
		handleUdpSession(cConn, payload[:RLen])
	} else {
		if config.Enable_httpDNS == false || Respond_HttpDNS(cConn, payload[:RLen]) == false { /*优先处理httpDNS请求*/
			if WLen, err := cConn.Write(rspHeader(payload[:RLen])); err != nil || WLen &lt;= 0 {
				cConn.Close()
				return
			}
			/* 转为tls的conn */
			if tlsConfig != nil {
				cConn = tls.Server(cConn, tlsConfig)
			}
			if bytes.Contains(payload[:RLen], []byte(config.Udp_flag)) == true {
				handleUdpSession(cConn, nil)
			} else {
				handleTcpSession(cConn, payload)
			}
		}
	}
}

func startHttpTunnel(listen_addr string) {
	var conn *net.TCPConn

	listener, err := net.Listen(&quot;tcp&quot;, listen_addr)
	if config.Enable_TFO {
		enableTcpFastopen(listener)
	}
	defer listener.Close()
	if err != nil {
		log.Println(err)
		return
	}
	tcpListener := listener.(*net.TCPListener)

	for {
		conn, err = tcpListener.AcceptTCP()
		if err != nil {
			log.Println(err)
			time.Sleep(3 * time.Second)
			continue
		}
		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(time.Minute)
		go handleTunnel(conn, tcpBufferPool.Get().([]byte), config.Tls.tlsConfig)
	}
}

package master

import (
	&quot;encoding/json&quot;
	&quot;flag&quot;
	&quot;fmt&quot;
	&quot;io/ioutil&quot;
	&quot;log&quot;
	&quot;os&quot;
	&quot;os/exec&quot;
	&quot;os/signal&quot;
	&quot;runtime&quot;
	&quot;syscall&quot;
	&quot;time&quot;
)

type JsonConfig struct {
	Tls                                               TlsServer
	Listen_addr                                       []string
	Proxy_key, Udp_flag, Encrypt_password, Pid_path   string
	Tcp_timeout, Udp_timeout                          time.Duration
	Enable_dns_tcpOverUdp, Enable_httpDNS, Enable_TFO bool
}

var config = JsonConfig{
	Proxy_key:   &quot;Host&quot;,
	Udp_flag:    &quot;httpUDP&quot;,
	Tcp_timeout: 600,
	Udp_timeout: 30,
}

func jsonLoad(filename string, v *JsonConfig) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
		return
	}
	err = json.Unmarshal(data, v)
	if err != nil {
		log.Fatal(err)
		return
	}
}

func pidSaveToFile(pidPath string) {
	fp, err := os.Create(pidPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	fp.WriteString(fmt.Sprintf(&quot;%d&quot;, os.Getpid()))
	if err != nil {
		fmt.Println(err)
	}
	fp.Close()
}

func handleCmd() {
	var (
		err                 error
		jsonConfigPath      string
		help, enable_daemon bool
	)

	flag.StringVar(&amp;jsonConfigPath, &quot;json&quot;, &quot;&quot;, &quot;json config path&quot;)
	flag.BoolVar(&amp;enable_daemon, &quot;daemon&quot;, false, &quot;daemon mode switch&quot;)
	flag.BoolVar(&amp;help, &quot;h&quot;, false, &quot;&quot;)
	flag.BoolVar(&amp;help, &quot;help&quot;, false, &quot;display this message&quot;)

	flag.Parse()
	if help == true {
		fmt.Println(&quot;　/) /)\n&quot; +
			&quot;ฅ(՞•ﻌ•՞)ฅ\n&quot; +
			&quot;CuteBi Network Server 0.4\nAuthor: CuteBi(Mmmdbybyd)\nE-mail: supercutename@gmail.com\n&quot;)
		flag.Usage()
		os.Exit(0)
	}
	if jsonConfigPath == &quot;&quot; {
		flag.Usage()
		fmt.Println(&quot;\n\nFind&apos;t json config file&quot;)
		os.Exit(1)
	}
	if enable_daemon == true {
		/*
			cmd := exec.Command(os.Args[0], []string(append(os.Args[1:], &quot;-daemon=false&quot;))...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			cmd.Start()
		*/
		exec.Command(os.Args[0], []string(append(os.Args[1:], &quot;-daemon=false&quot;))...).Start()
		os.Exit(0)
	}
	jsonLoad(jsonConfigPath, &amp;config)

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if config.Pid_path != &quot;&quot; {
		pidSaveToFile(config.Pid_path)
	}
	config.Enable_httpDNS = true
	config.Proxy_key = &quot;\n&quot; + config.Proxy_key + &quot;: &quot;
	CuteBi_XorCrypt_password = []byte(config.Encrypt_password)
	config.Tcp_timeout *= time.Second
	config.Udp_timeout *= time.Second
}

func strarChileProc() {
	if os.Getenv(&quot;CHILD_PORC&quot;) != &quot;true&quot; {
		var runCmd exec.Cmd

		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = []string{&quot;CHILD_PORC=true&quot;}
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
		go func() {
			&lt;-sigCh
			cmd = nil
			runCmd.Process.Kill()
		}()
		for {
			if cmd == nil {
				os.Exit(1)
			}
			//同一个内存的exec.Cmd不能重复启动程序，所以需要复制到新的内存
			runCmd = *cmd
			runCmd.Run()
		}
	}
}

func initProcess() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	handleCmd()
	strarChileProc()
	setsid()
	setMaxNofile()
	signal.Ignore(syscall.SIGPIPE)
}

func master() {
	initProcess()
	//有效uid不为0(root)的关闭tfo
	if config.Enable_TFO == true &amp;&amp; os.Geteuid() != 0 {
		config.Enable_TFO = false
		fmt.Println(&quot;Warnning: TFO cannot be opened: CNS effective UID isn&apos;t 0(root).&quot;)
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	if len(config.Tls.Listen_addr) &gt; 0 {
		config.Tls.makeCertificateConfig()
		for i := len(config.Tls.Listen_addr) - 1; i &gt;= 0; i-- {
			go config.Tls.startTls(config.Tls.Listen_addr[i])
		}
	}
	for i := len(config.Listen_addr) - 1; i &gt;= 0; i-- {
		go startHttpTunnel(config.Listen_addr[i])
	}
	select {}
}

package master

import (
	&quot;bytes&quot;
	&quot;fmt&quot;
	&quot;log&quot;
	&quot;net&quot;
	&quot;strings&quot;
	&quot;time&quot;
)

func dns_tcpOverUdp(cConn net.Conn, host string, buffer []byte) {
	// log.Println(&quot;Start dns_tcpOverUdp&quot;)
	defer cConn.Close()

	var err error
	var WLen, RLen, payloadLen, CuteBi_XorCrypt_passwordSub int
	var pkgLen uint16
	for {
		cConn.SetReadDeadline(time.Now().Add(config.Tcp_timeout))
		RLen, err = cConn.Read(buffer[payloadLen:])
		if RLen &lt;= 0 || err != nil {
			log.Println(&quot;cConn.Read():&quot;, err)
			return
		}
		//解密
		if len(CuteBi_XorCrypt_password) != 0 {
			CuteBi_XorCrypt_passwordSub = CuteBi_XorCrypt(buffer[payloadLen:payloadLen+RLen], CuteBi_XorCrypt_passwordSub)
		}
		payloadLen += RLen
		if payloadLen &gt; 2 {
			pkgLen = (uint16(buffer[0]) &lt;&lt; 8) | (uint16(buffer[1])) //包长度转换
			//防止访问非法数据
			if int(pkgLen)+2 &gt; len(buffer) {
				return
			}
			//如果读取到了一个完整的包，就跳出循环
			if int(pkgLen)+2 &lt;= payloadLen {
				break
			}
		}
	}
	/* 连接目标地址 */
	sConn, dialErr := net.Dial(&quot;udp&quot;, host)
	if dialErr != nil {
		log.Println(dialErr)
		cConn.Write([]byte(&quot;Proxy address [&quot; + host + &quot;] DNS Dial() error&quot;))
		return
	}
	defer sConn.Close()
	if WLen, err = sConn.Write(buffer[2:payloadLen]); WLen &lt;= 0 || err != nil {
		log.Println(&quot;sConn.Write():&quot;, err)
		return
	}
	sConn.SetReadDeadline(time.Now().Add(config.Udp_timeout))
	if RLen, err = sConn.Read(buffer[2:]); RLen &lt;= 0 || err != nil {
		log.Println(&quot;sConn.Read():&quot;, err)
		return
	}
	// log.Println(&quot;sConn.Read():&quot;, RLen)
	//包长度转换
	buffer[0] = byte(RLen &gt;&gt; 8)
	buffer[1] = byte(RLen)
	//加密
	if len(CuteBi_XorCrypt_password) != 0 {
		CuteBi_XorCrypt(buffer[:2+RLen], 0)
	}
	cConn.Write(buffer[:2+RLen])
}

func Respond_HttpDNS(cConn net.Conn, header []byte) bool {
	var domainBegin string
	httpDNS_DomainSub := bytes.Index(header[:], []byte(&quot;dn=&quot;))
	if httpDNS_DomainSub &lt; 0 {
		return false
	}
	if _, err := fmt.Sscanf(string(header[httpDNS_DomainSub+3:]), &quot;%s&quot;, &amp;domainBegin); err != nil {
		log.Println(err)
		return false
	}
	domain := strings.Split(domainBegin, &quot;&amp;&quot;)
	//log.Println(&quot;httpDNS domain: [&quot; + domain[0] + &quot;]&quot;)
	defer cConn.Close()
	ips, err := net.LookupHost(domain[0])
	if err != nil {
		cConn.Write([]byte(&quot;HTTP/1.0 404 Not Found\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%&gt;w&lt;%)\r\nContent-type: charset=utf-8\r\n\r\n&lt;html&gt;&lt;head&gt;&lt;title&gt;HTTP DNS Server&lt;/title&gt;&lt;/head&gt;&lt;body&gt;查询域名失败&lt;br/&gt;&lt;br/&gt;By: 萌萌萌得不要不要哒&lt;br/&gt;E-mail: 915445800@qq.com&lt;/body&gt;&lt;/html&gt;&quot;))
		//log.Println(&quot;httpDNS domain: [&quot; + domain[0] + &quot;], Lookup failed&quot;)
	} else {
		isIpv6 := bytes.Contains(header[:], []byte(&quot;type=AAAA&quot;))
		for i := 0; i &lt; len(ips); i++ {
			if strings.Contains(ips[i], &quot;:&quot;) /*只有ipv6才包含&apos;:&apos;*/ == isIpv6 {
				if bytes.Contains(header[:], []byte(&quot;ttl=1&quot;)) {
					ips[i] += &quot;,60&quot;
				}
				fmt.Fprintf(cConn, &quot;HTTP/1.0 200 OK\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%%&gt;w&lt;%%)\r\nContent-Length: %d\r\n\r\n%s&quot;, len(ips[i]), ips[i])
				break
			}
		}
		//log.Println(&quot;httpDNS domain: [&quot;+domain[0]+&quot;], IPS: &quot;, ips)
	}
	return true
}

package master

import (
	&quot;bytes&quot;
	&quot;crypto/tls&quot;
	&quot;log&quot;
	&quot;net&quot;
	&quot;time&quot;
)

func isHttpHeader(header []byte) bool {
	if bytes.HasPrefix(header, []byte(&quot;CONNECT&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;GET&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;POST&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;HEAD&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;PUT&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;COPY&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;DELETE&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;MOVE&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;OPTIONS&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;LINK&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;UNLINK&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;TRACE&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;PATCH&quot;)) == true ||
		bytes.HasPrefix(header, []byte(&quot;WRAPPED&quot;)) == true {
		return true
	}
	return false
}

func rspHeader(header []byte) []byte {
	if bytes.Contains(header, []byte(&quot;WebSocket&quot;)) == true {
		return []byte(&quot;HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: CuteBi Network Tunnel, (%&gt;w&lt;%)\r\n\r\n&quot;)
	} else if bytes.HasPrefix(header, []byte(&quot;CON&quot;)) == true {
		return []byte(&quot;HTTP/1.1 200 Connection established\r\nServer: CuteBi Network Tunnel, (%&gt;w&lt;%)\r\nConnection: keep-alive\r\n\r\n&quot;)
	} else {
		return []byte(&quot;HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: CuteBi Network Tunnel, (%&gt;w&lt;%)\r\nConnection: keep-alive\r\n\r\n&quot;)
	}
}

func handleTunnel(cConn net.Conn, payload []byte, tlsConfig *tls.Config) {
	defer tcpBufferPool.Put(payload)

	cConn.SetReadDeadline(time.Now().Add(config.Tcp_timeout))
	RLen, err := cConn.Read(payload)
	if err != nil || RLen &lt;= 0 {
		cConn.Close()
		return
	}
	if isHttpHeader(payload[:RLen]) == false {
		/* 转为tls的conn */
		if tlsConfig != nil {
			cConn = tls.Server(cConn, tlsConfig)
		}
		handleUdpSession(cConn, payload[:RLen])
	} else {
		if config.Enable_httpDNS == false || Respond_HttpDNS(cConn, payload[:RLen]) == false { /*优先处理httpDNS请求*/
			if WLen, err := cConn.Write(rspHeader(payload[:RLen])); err != nil || WLen &lt;= 0 {
				cConn.Close()
				return
			}
			/* 转为tls的conn */
			if tlsConfig != nil {
				cConn = tls.Server(cConn, tlsConfig)
			}
			if bytes.Contains(payload[:RLen], []byte(config.Udp_flag)) == true {
				handleUdpSession(cConn, nil)
			} else {
				handleTcpSession(cConn, payload)
			}
		}
	}
}

func startHttpTunnel(listen_addr string) {
	var conn *net.TCPConn

	listener, err := net.Listen(&quot;tcp&quot;, listen_addr)
	if config.Enable_TFO {
		enableTcpFastopen(listener)
	}
	defer listener.Close()
	if err != nil {
		log.Println(err)
		return
	}
	tcpListener := listener.(*net.TCPListener)

	for {
		conn, err = tcpListener.AcceptTCP()
		if err != nil {
			log.Println(err)
			time.Sleep(3 * time.Second)
			continue
		}
		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(time.Minute)
		go handleTunnel(conn, tcpBufferPool.Get().([]byte), config.Tls.tlsConfig)
	}
}

// +build !windows

package master

import (
	&quot;log&quot;
	&quot;net&quot;
	&quot;syscall&quot;
)

func setMaxNofile() {
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &amp;syscall.Rlimit{Cur: 1048576, Max: 1048576})
}

func setsid() {
	syscall.Setsid()
}

func enableTcpFastopen(listener net.Listener) {
	const CNS_TCP_FASTOPEN int = 0x17
	f, _ := listener.(*net.TCPListener).File()
	if err := syscall.SetsockoptInt(int(f.Fd()), syscall.IPPROTO_TCP, CNS_TCP_FASTOPEN, 1); err != nil {
		log.Println(err)
	}
	f.Close()
}

// +build windows

// isWin.go
package master

import (
	&quot;log&quot;
	&quot;net&quot;
	&quot;syscall&quot;
)

func setMaxNofile() {
}

func setsid() {
}

func enableTcpFastopen(listener net.Listener) {
	const CNS_TCP_FASTOPEN int = 0x17
	f, err := listener.(*net.TCPListener).File()
	if err != nil {
		log.Println(err)
		return
	}
	if err := syscall.SetsockoptInt(syscall.Handle(f.Fd()), syscall.IPPROTO_TCP, CNS_TCP_FASTOPEN, 1); err != nil {
		log.Println(err)
	}
	f.Close()
}

package master

import (
	&quot;bytes&quot;
	&quot;log&quot;
	&quot;net&quot;
	&quot;strings&quot;
	&quot;sync&quot;
	&quot;time&quot;
)

var tcpBufferPool sync.Pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 8192)
	},
}

/* 把fromConn的数据转发到toConn */
func tcpForward(fromConn, toConn net.Conn, payload []byte) {
	defer func() {
		fromConn.Close()
		toConn.Close()
	}()

	var RLen, WLen, CuteBi_XorCrypt_passwordSub int
	var err error
	for {
		fromConn.SetReadDeadline(time.Now().Add(config.Tcp_timeout))
		toConn.SetReadDeadline(time.Now().Add(config.Tcp_timeout))
		if RLen, err = fromConn.Read(payload); err != nil || RLen &lt;= 0 {
			return
		}
		if len(CuteBi_XorCrypt_password) != 0 {
			CuteBi_XorCrypt_passwordSub = CuteBi_XorCrypt(payload[:RLen], CuteBi_XorCrypt_passwordSub)
		}
		toConn.SetWriteDeadline(time.Now().Add(config.Tcp_timeout))
		if WLen, err = toConn.Write(payload[:RLen]); err != nil || WLen &lt;= 0 {
			return
		}
	}
}

/* 从header中获取host */
func getProxyHost(header []byte) string {
	hostSub := bytes.Index(header, []byte(config.Proxy_key))
	if hostSub &lt; 0 {
		return &quot;&quot;
	}
	hostSub += len(config.Proxy_key)
	hostEndSub := bytes.IndexByte(header[hostSub:], &apos;\r&apos;)
	if hostEndSub &lt; 0 {
		return &quot;&quot;
	}
	hostEndSub += hostSub
	if len(CuteBi_XorCrypt_password) != 0 {
		host, err := CuteBi_decrypt_host(header[hostSub:hostEndSub])
		if err != nil {
			log.Println(err)
			return &quot;&quot;
		}
		return string(host)
	} else {
		return string(header[hostSub:hostEndSub])
	}
}

/* 处理tcp会话 */
func handleTcpSession(cConn net.Conn, header []byte) {
	// defer log.Println(&quot;A tcp client close&quot;)

	/* 获取请求头中的host */
	host := getProxyHost(header)
	if host == &quot;&quot; {
		log.Println(&quot;No proxy host: {&quot; + string(header) + &quot;}&quot;)
		cConn.Write([]byte(&quot;No proxy host&quot;))
		cConn.Close()
		return
	}
	// log.Println(&quot;proxyHost: &quot; + host)
	//tcpDNS over udpDNS
	if config.Enable_dns_tcpOverUdp &amp;&amp; strings.HasSuffix(host, &quot;:53&quot;) == true {
		dns_tcpOverUdp(cConn, host, header)
		return
	}
	/* 连接目标地址 */
	if strings.Contains(host, &quot;:&quot;) == false {
		host += &quot;:80&quot;
	}
	sConn, dialErr := net.Dial(&quot;tcp&quot;, host)
	if dialErr != nil {
		log.Println(dialErr)
		cConn.Write([]byte(&quot;Proxy address [&quot; + host + &quot;] DialTCP() error&quot;))
		cConn.Close()
		return
	}
	/* 开始转发 */
	// log.Println(&quot;Start tcpForward&quot;)

	go tcpForward(cConn, sConn, header)
	newBuff := tcpBufferPool.Get().([]byte)
	tcpForward(sConn, cConn, newBuff)
	tcpBufferPool.Put(newBuff)
}

package master

import (
	&quot;crypto/ecdsa&quot;
	&quot;crypto/elliptic&quot;
	&quot;crypto/rand&quot;
	&quot;crypto/tls&quot;
	&quot;crypto/x509&quot;
	&quot;crypto/x509/pkix&quot;
	&quot;encoding/pem&quot;
	&quot;log&quot;
	&quot;math/big&quot;
	&quot;net&quot;
	&quot;time&quot;
)

type TlsServer struct {
	Listen_addr, AutoCertHosts []string
	CertFile, KeyFile          string
	tlsConfig                  *tls.Config
}

func createCertificate(hosts string) ([]byte, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf(&quot;Failed to generate serial number: %v&quot;, err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{&quot;Acme Co&quot;},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		/*if ip := net.ParseIP(string(h)); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {*/
		template.DNSNames = append(template.DNSNames, string(h))
		//}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &amp;template, &amp;template, &amp;priv.PublicKey, priv)
	if err != nil {
		log.Fatalf(&quot;Failed to create certificate: %v&quot;, err)
	}
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&amp;pem.Block{Type: &quot;PRIVATE KEY&quot;, Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&amp;pem.Block{Type: &quot;CERTIFICATE&quot;, Bytes: certDER})

	return certPEM, keyPEM
}

func (cnsTls *TlsServer) makeCertificateConfig() {
	certs := make([]tls.Certificate, 0)
	if cnsTls.CertFile != &quot;&quot; &amp;&amp; cnsTls.KeyFile != &quot;&quot; {
		cer, err := tls.LoadX509KeyPair(cnsTls.CertFile, cnsTls.KeyFile)
		if err != nil {
			log.Println(err)
			return
		}
		certs = append(certs, cer)
	} else {
		if cnsTls.AutoCertHosts == nil {
			cnsTls.AutoCertHosts = []string{&quot;&quot;}
		}
		for _, h := range cnsTls.AutoCertHosts {
			cer, err := tls.X509KeyPair(createCertificate(h))
			if err != nil {
				log.Println(err)
				return
			}
			certs = append(certs, cer)
		}
	}
	cnsTls.tlsConfig = &amp;tls.Config{Certificates: certs}
}

func (cnsTls *TlsServer) startTls(listen_addr string) {
	var conn *net.TCPConn

	listener, err := net.Listen(&quot;tcp&quot;, listen_addr)
	if config.Enable_TFO {
		enableTcpFastopen(listener)
	}
	defer listener.Close()
	if err != nil {
		log.Println(err)
		return
	}
	tcpListener := listener.(*net.TCPListener)

	for {
		conn, err = tcpListener.AcceptTCP()
		if err != nil {
			log.Println(err)
			time.Sleep(3 * time.Second)
			continue
		}
		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(time.Minute)
		go handleTunnel(tls.Server(conn, cnsTls.tlsConfig), tcpBufferPool.Get().([]byte), nil)
	}
}

package master

import (
	&quot;bytes&quot;
	&quot;log&quot;
	&quot;net&quot;
	&quot;sync&quot;
	&quot;time&quot;
)

type UdpSession struct {
	cConn                                                            net.Conn
	udpSConn                                                         *net.UDPConn
	c2s_CuteBi_XorCrypt_passwordSub, s2c_CuteBi_XorCrypt_passwordSub int
}

var udpBufferPool sync.Pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}

func (udpSess *UdpSession) udpServerToClient() {

	/* 不要在for里用:=申请变量, 否则每次循环都会重新申请内存 */
	var (
		RAddr                              *net.UDPAddr
		payload_len, ignore_head_len, WLen int
		err                                error
	)
	payload := udpBufferPool.Get().([]byte)

	defer func() {
		udpBufferPool.Put(payload)
		udpSess.cConn.Close()
		udpSess.udpSConn.Close()
	}()

	for {
		udpSess.cConn.SetReadDeadline(time.Now().Add(config.Udp_timeout))
		udpSess.udpSConn.SetReadDeadline(time.Now().Add(config.Udp_timeout))
		payload_len, RAddr, err = udpSess.udpSConn.ReadFromUDP(payload[24:] /*24为httpUDP协议头保留使用*/)
		if err != nil || payload_len &lt;= 0 {
			return
		}
		//fmt.Println(&quot;readUdpServerLen: &quot;, payload_len, &quot;RAddr: &quot;, RAddr.String())
		if bytes.HasPrefix(RAddr.IP, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}) == true {
			/* ipv4 */
			ignore_head_len = 12                 //数组前面的12字节不需要
			payload[12] = byte(payload_len + 10) //从第13个字节开始设置协议头
			payload[13] = byte((payload_len + 10) &gt;&gt; 8)
			copy(payload[14:18], []byte{0, 0, 0, 1})
			copy(payload[18:22], []byte(RAddr.IP)[12:16])
		} else {
			/* ipv6 */
			ignore_head_len = 0
			payload[0] = byte(payload_len + 22)
			payload[1] = byte((payload_len + 22) &gt;&gt; 8)
			copy(payload[2:6], []byte{0, 0, 0, 3})
			copy(payload[6:22], []byte(RAddr.IP))
		}
		payload[22] = byte(RAddr.Port &gt;&gt; 8)
		payload[23] = byte(RAddr.Port)
		if len(CuteBi_XorCrypt_password) != 0 {
			udpSess.s2c_CuteBi_XorCrypt_passwordSub = CuteBi_XorCrypt(payload[ignore_head_len:24+payload_len], udpSess.s2c_CuteBi_XorCrypt_passwordSub)
		}
		udpSess.cConn.SetWriteDeadline(time.Now().Add(config.Udp_timeout))
		if WLen, err = udpSess.cConn.Write(payload[ignore_head_len : 24+payload_len]); err != nil || WLen &lt;= 0 {
			return
		}
	}
}

func (udpSess *UdpSession) writeToServer(httpUDP_data []byte) int {
	var (
		udpAddr                           net.UDPAddr
		err                               error
		WLen                              int
		pkgSub, httpUDP_protocol_head_len int
		pkgLen                            uint16
	)
	for pkgSub = 0; pkgSub+2 &lt; len(httpUDP_data); pkgSub += 2 + int(pkgLen) {
		pkgLen = uint16(httpUDP_data[pkgSub]) | (uint16(httpUDP_data[pkgSub+1]) &lt;&lt; 8) //2字节储存包的长度，包括socks5头
		//log.Println(&quot;pkgSub: &quot;, pkgSub, &quot;, pkgLen: &quot;, pkgLen, &quot;  &quot;, uint16(len(httpUDP_data)))
		if pkgSub+2+int(pkgLen) &gt; len(httpUDP_data) || pkgLen &lt;= 10 {
			return 0
		}
		if bytes.HasPrefix(httpUDP_data[pkgSub+3:pkgSub+5], []byte{0, 0}) == false {
			return 1
		}
		if httpUDP_data[5] == 1 {
			/* ipv4 */
			udpAddr.IP = net.IPv4(httpUDP_data[pkgSub+6], httpUDP_data[pkgSub+7], httpUDP_data[pkgSub+8], httpUDP_data[pkgSub+9])
			udpAddr.Port = int((uint16(httpUDP_data[pkgSub+10]) &lt;&lt; 8) | uint16(httpUDP_data[pkgSub+11]))
			httpUDP_protocol_head_len = 12
		} else {
			if pkgLen &lt;= 24 {
				return 0
			}
			/* ipv6 */
			udpAddr.IP = net.IP(httpUDP_data[pkgSub+6 : pkgSub+22])
			udpAddr.Port = int((uint16(httpUDP_data[pkgSub+22]) &lt;&lt; 8) | uint16(httpUDP_data[pkgSub+23]))
			httpUDP_protocol_head_len = 24
		}
		//log.Println(&quot;WriteToUdpAddr: &quot;, udpAddr.String())
		if WLen, err = udpSess.udpSConn.WriteToUDP(httpUDP_data[pkgSub+httpUDP_protocol_head_len:pkgSub+2+int(pkgLen)], &amp;udpAddr); err != nil || WLen &lt;= 0 {
			return -1
		}
	}

	return int(pkgSub)
}

func (udpSess *UdpSession) udpClientToServer(httpUDP_data []byte) {
	var payload_len, RLen, WLen int
	var err error
	payload := udpBufferPool.Get().([]byte)

	defer func() {
		udpBufferPool.Put(payload)
		udpSess.cConn.Close()
		udpSess.udpSConn.Close()
	}()

	if httpUDP_data != nil {
		WLen = udpSess.writeToServer(httpUDP_data)
		if WLen == -1 {
			return
		}
		if WLen &lt; len(httpUDP_data) {
			payload_len = copy(payload, httpUDP_data[WLen:])
		}
	}
	for {
		udpSess.cConn.SetReadDeadline(time.Now().Add(config.Udp_timeout))
		udpSess.udpSConn.SetReadDeadline(time.Now().Add(config.Udp_timeout))
		RLen, err = udpSess.cConn.Read(payload[payload_len:])
		if err != nil || RLen &lt;= 0 {
			return
		}
		if len(CuteBi_XorCrypt_password) != 0 {
			udpSess.c2s_CuteBi_XorCrypt_passwordSub = CuteBi_XorCrypt(payload[payload_len:payload_len+RLen], udpSess.c2s_CuteBi_XorCrypt_passwordSub)
		}
		payload_len += RLen
		//log.Println(&quot;Read Client: &quot;, payload_len)
		WLen = udpSess.writeToServer(payload[:payload_len])
		if WLen == -1 {
			return
		} else if WLen &lt; payload_len {
			payload_len = copy(payload, payload[WLen:payload_len])
		} else {
			payload_len = 0
		}
	}
}

func (udpSess *UdpSession) initUdp(httpUDP_data []byte) bool {
	if httpUDP_data != nil &amp;&amp; len(CuteBi_XorCrypt_password) != 0 {
		de := make([]byte, 5)
		copy(de, httpUDP_data[0:5])
		CuteBi_XorCrypt(de, 0)
		if de[2] != 0 || de[3] != 0 || de[4] != 0 {
			return false
		}
		udpSess.c2s_CuteBi_XorCrypt_passwordSub = CuteBi_XorCrypt(httpUDP_data, 0)
	}
	var err error
	udpSess.udpSConn, err = net.ListenUDP(&quot;udp&quot;, nil)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func handleUdpSession(cConn net.Conn, httpUDP_data []byte) {
	//defer log.Println(&quot;A udp client close&quot;)

	udpSess := new(UdpSession)
	udpSess.cConn = cConn
	if udpSess.initUdp(httpUDP_data) == false {
		cConn.Close()
		log.Println(&quot;Is not httpUDP protocol or Decrypt failed&quot;)
		return
	}
	//log.Println(&quot;Start udpForward&quot;)
	go udpSess.udpClientToServer(httpUDP_data)
	udpSess.udpServerToClient()
}
