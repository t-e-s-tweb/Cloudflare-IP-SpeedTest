package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	requestURL  = "speed.cloudflare.com/cdn-cgi/trace" // 请求trace URL
	timeout     = 1 * time.Second                      // 超时时间
	maxDuration = 2 * time.Second                      // 最大持续时间
)

var (
	File         = flag.String("file", "ip.txt", "IP地址文件名称")                                   // IP地址文件名称
	scanAllIPs   = flag.Bool("scanallips", false, "是否自动获取优选IP")                                // 自动获取Github上分享的优选IP
	outFile      = flag.String("outfile", "ip.csv", "输出文件名称")                                  // 输出文件名称
	defaultPort  = flag.Int("port", 443, "端口")                                                 // 端口
	maxThreads   = flag.Int("max", 100, "并发请求最大协程数")                                           // 最大协程数
	speedTest    = flag.Int("speedtest", 5, "下载测速协程数量,设为0禁用测速")                                // 下载测速协程数量
	speedTestURL = flag.String("url", "speed.cloudflare.com/__down?bytes=500000000", "测速文件地址") // 测速文件地址
	enableTLS    = flag.Bool("tls", true, "是否启用TLS")                                           // TLS是否启用
	SSJson       = flag.String("ssjson", "sslocal.json", "ShadowSocks配置文件")
)

var URLList = []string{
	"https://mirror.ghproxy.com/https://github.com/ip-scanner/cloudflare/archive/refs/heads/main.tar.gz",
	"https://mirror.ghproxy.com/https://github.com/ymyuuu/IPDB/archive/refs/heads/main.tar.gz",
}

type result struct {
	ip          string        // IP地址
	port        int           // 端口
	dataCenter  string        // 数据中心
	region      string        // 地区
	city        string        // 城市
	latency     string        // 延迟
	tcpDuration time.Duration // TCP请求延迟
}

type speedtestresult struct {
	result
	downloadSpeed float64 // 下载速度
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// Downloader 结构体用于组织下载相关的方法和状态
type Downloader struct {
	client *http.Client
}

// NewDownloader 返回一个初始化的 Downloader 实例
func NewDownloader() *Downloader {
	return &Downloader{
		client: &http.Client{},
	}
}

type ShadowsocksConfig struct {
	Host       string
	Port       int
	Method     string
	Password   string
	Plugin     string
	PluginOpts string
}

// ServerConfig 结构体表示单个服务器的配置
type ServerConfig struct {
	Disabled   bool   `json:"disabled"`
	Mode       string `json:"mode"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
	Plugin     string `json:"plugin"`
	PluginOpts string `json:"plugin_opts"`
}

// ServerList 结构体表示服务器列表
type ServerList struct {
	Servers []ServerConfig `json:"servers"`
}

func main() {
	flag.Parse()
	// 尝试提升文件描述符的上限
	osType := runtime.GOOS
	if osType == "linux" {
		increaseMaxOpenFiles()
	}
	// 进行测速
	if err := speedtest(); err != nil {
		handleError(err, "Error during speedtest")
	} else {
		fmt.Println("Speedtest completed successfully.")
	}
}

func handleError(err error, message string) {
	if err != nil {
		fmt.Printf("%s：%v\n", message, err)
		os.Exit(1)
	}
}

// 尝试提升文件描述符的上限
func increaseMaxOpenFiles() {
	fmt.Println("正在尝试提升文件描述符的上限...")
	cmd := exec.Command("bash", "-c", "ulimit -n 10000")
	_, err := cmd.CombinedOutput()
	if err != nil {
		handleError(err, "提升文件描述符上限时出现错误")
	} else {
		fmt.Printf("文件描述符上限已提升!\n")
	}
}

func speedtest() error {
	startTime := time.Now()
	var locations []location
	var ips []string

	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在\n正在从 https://speed.cloudflare.com/locations 下载 locations.json")
		resp, err := http.Get("https://speed.cloudflare.com/locations")
		if err != nil {
			handleError(err, "无法从URL中获取JSON")
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			handleError(err, "无法读取响应体")
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			handleError(err, "无法解析JSON")
		}
		file, err := os.Create("locations.json")
		if err != nil {
			handleError(err, "无法创建文件")
		}
		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			handleError(err, "无法写入文件")
		}
	} else {
		fmt.Println("本地 locations.json 已存在,无需重新下载")
		file, err := os.Open("locations.json")
		if err != nil {
			handleError(err, "无法打开文件")
		}
		defer file.Close()

		body, err := ioutil.ReadAll(file)
		if err != nil {
			handleError(err, "无法读取文件")
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			handleError(err, "无法解析JSON")
		}
	}

	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}

	// 从文件中读取 IP 地址
	ips, err := readIPs(*File)
	if err != nil {
		fmt.Printf("无法从文件中读取 IP: %v\n", err)
	}

	// 如果需要扫描所有 IP 或者读取 IP 错误，执行以下操作
	if *scanAllIPs || err != nil {
		var wg sync.WaitGroup
		downloader := NewDownloader()
		for _, url := range URLList {
			wg.Add(1)
			errCh := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			go func(url string, errCh chan<- error, ctx context.Context) {
				defer wg.Done()
				defer cancel()

				fmt.Printf("Downloading %s...\n", url)
				err := downloader.downloadAndExtract(url, errCh, ctx)
				if err != nil {
					handleError(err, "Error")
				} else {
					fmt.Printf("Finished downloading and extracting %s\n", url)
				}
			}(url, errCh, ctx)

			select {
			case <-ctx.Done():
				fmt.Printf("Timed out downloading %s\n", url)
			case err := <-errCh:
				if err != nil {
					fmt.Println("Error:", err)
					return err
					os.Exit(1)
				}
			}
		}

		wg.Wait()
		// 下载和解压文件
		var ipv4Addresses, ipv6Addresses []string
		ipv4Addresses, ipv6Addresses, err := findIPAddresses(filepath.Join(".", "temp"))
		if err != nil {
			fmt.Println("Error finding IP addresses:", err)
			return err
		}
		// 在函数退出时删除临时文件夹及其内容
		if err := os.RemoveAll(filepath.Join(".", "temp")); err != nil {
			handleError(err, "Error cleaning up temporary files")
		}

		ips = append(ips, ipv4Addresses...)
		ips = append(ips, ipv6Addresses...)
	}
	// 遍历 IP 地址，执行测速操作
	var wg sync.WaitGroup
	wg.Add(len(ips))

	resultChan := make(chan result, len(ips))

	thread := make(chan struct{}, *maxThreads)

	var count int
	total := len(ips)

	for _, ip := range ips {
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				count++
				percentage := float64(count) / float64(total) * 100
				fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", count, total, percentage)
				if count == total {
					fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\n", count, total, percentage)
				}
			}()

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(*defaultPort)))
			if err != nil {
				return
			}
			defer conn.Close()

			tcpDuration := time.Since(start)
			start = time.Now()

			client := http.Client{
				Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return conn, nil
					},
				},
				Timeout: timeout,
			}

			var protocol string
			if *enableTLS {
				protocol = "https://"
			} else {
				protocol = "http://"
			}
			requestURL := protocol + requestURL

			req, _ := http.NewRequest("GET", requestURL, nil)

			// 添加用户代理
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return
			}

			duration := time.Since(start)
			if duration > maxDuration {
				return
			}

			buf := &bytes.Buffer{}
			// 创建一个读取操作的超时
			timeout := time.After(maxDuration)
			// 使用一个 goroutine 来读取响应体
			done := make(chan bool)
			go func() {
				_, err := io.Copy(buf, resp.Body)
				done <- true
				if err != nil {
					return
				}
			}()
			// 等待读取操作完成或者超时
			select {
			case <-done:
				// 读取操作完成
			case <-timeout:
				// 读取操作超时
				return
			}

			body := buf
			if err != nil {
				return
			}

			if strings.Contains(body.String(), "uag=Mozilla/5.0") {
				if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(body.String()); len(matches) > 1 {
					dataCenter := matches[1]
					loc, ok := locationMap[dataCenter]
					if ok {
						fmt.Printf("发现有效IP %s 位置信息 %s 延迟 %d 毫秒\n", ip, loc.City, tcpDuration.Milliseconds())
						resultChan <- result{ip, *defaultPort, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration}
					} else {
						fmt.Printf("发现有效IP %s 位置信息未知 延迟 %d 毫秒\n", ip, tcpDuration.Milliseconds())
						resultChan <- result{ip, *defaultPort, dataCenter, "", "", fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration}
					}
				}
			}
		}(ip)
	}
	// 等待所有 goroutine 完成
	wg.Wait()
	close(resultChan)

	if len(resultChan) == 0 {
		// 清除输出内容
		fmt.Print("\033[2J")
		fmt.Println("没有发现有效的IP")
		return nil
	}
	var results []speedtestresult
	if *speedTest > 0 {
		fmt.Printf("开始测速\n")
		var wg2 sync.WaitGroup
		wg2.Add(*speedTest)
		count = 0
		total := len(resultChan)
		results = []speedtestresult{}
		for i := 0; i < *speedTest; i++ {
			thread <- struct{}{}
			go func() {
				defer func() {
					<-thread
					wg2.Done()
				}()
				for res := range resultChan {

					downloadSpeed := getDownloadSpeed(res.ip)
					if downloadSpeed > 0 {
						results = append(results, speedtestresult{result: res, downloadSpeed: downloadSpeed})
					}

					count++
					percentage := float64(count) / float64(total) * 100
					fmt.Printf("已完成: %.2f%%\r", percentage)
					if count == total {
						fmt.Printf("已完成: %.2f%%\033[0\n", percentage)
					}
				}
			}()
		}
		wg2.Wait()
	} else {
		for res := range resultChan {
			results = append(results, speedtestresult{result: res})
		}
	}

	if *speedTest > 0 {
		// 根据测速结果排序，然后写入 CSV 文件
		sort.Slice(results, func(i, j int) bool {
			return results[i].downloadSpeed > results[j].downloadSpeed
		})
	} else {
		sort.Slice(results, func(i, j int) bool {
			return results[i].result.tcpDuration < results[j].result.tcpDuration
		})
	}

	filecsv, err := os.Create(*outFile)
	if err != nil {
		handleError(err, "无法创建文件")
	}
	defer filecsv.Close()

	writer := csv.NewWriter(filecsv)
	if *speedTest > 0 {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市", "网络延迟", "下载速度"})
	} else {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市", "网络延迟"})
	}
	for _, res := range results {
		if *speedTest > 0 {
			writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.city, res.result.latency, fmt.Sprintf("%.0f kB/s", res.downloadSpeed)})
		} else {
			writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.city, res.result.latency})
		}
	}

	writer.Flush()

	if *SSJson != "" {
		configFile, err := ioutil.ReadFile(*SSJson)
		if err != nil {
			handleError(err, "无法读取配置文件")
		}

		if err := UpdateConfig(configFile, results); err != nil {
			handleError(err, "更新配置文件时发生错误件")
		}

		fmt.Println("新的配置已写入", *SSJson, "文件")
	}
	fmt.Printf("成功将结果写入文件 %s，耗时 %d秒\n", *outFile, time.Since(startTime)/time.Second)
	return nil
}

// 从文件中读取IP地址
func readIPs(File string) ([]string, error) {
	file, err := os.Open(File)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipAddr := scanner.Text()
		// 判断是否为 CIDR 格式的 IP 地址
		if strings.Contains(ipAddr, "/") {
			ip, ipNet, err := net.ParseCIDR(ipAddr)
			if err != nil {
				fmt.Errorf("无法解析CIDR格式的IP: %v\n", err)
				continue
			}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
				ips = append(ips, ip.String())
			}
		} else {
			ips = append(ips, ipAddr)
		}
	}
	return ips, scanner.Err()
}

// inc函数实现ip地址自增
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 测速函数
func getDownloadSpeed(ip string) float64 {
	var protocol string
	if *enableTLS {
		protocol = "https://"
	} else {
		protocol = "http://"
	}
	speedTestURL := protocol + *speedTestURL
	// 创建请求
	req, _ := http.NewRequest("GET", speedTestURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	// 创建TCP连接
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(*defaultPort)))
	if err != nil {
		return 0
	}
	defer conn.Close()

	fmt.Printf("正在测试IP %s 端口 %s\n", ip, strconv.Itoa(*defaultPort))
	startTime := time.Now()
	// 创建HTTP客户端
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		//设置单个IP测速最长时间为5秒
		Timeout: 5 * time.Second,
	}
	// 发送请求
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("IP %s 端口 %s 测速无效\n", ip, strconv.Itoa(*defaultPort))
		return 0
	}
	defer resp.Body.Close()

	// 复制响应体到/dev/null，并计算下载速度
	written, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(startTime)
	speed := float64(written) / duration.Seconds() / 1024

	// 输出结果
	fmt.Printf("IP %s 端口 %s 下载速度 %.0f kB/s\n", ip, strconv.Itoa(*defaultPort), speed)
	return speed
}

// downloadAndExtract 方法负责下载和解压文件
func (d *Downloader) downloadAndExtract(url string, errCh chan<- error, ctx context.Context) error {
	const maxRetries = 5
	var err error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fmt.Printf("正在下载 %s（尝试 %d）...\n", url, retry+1)
			err = d.downloadAndExtractOnce(url)
			if err == nil {
				fmt.Printf("完成下载和解压 %s\n", url)
				return nil
			}
			handleError(err, "错误")
		}
	}

	return fmt.Errorf("在 %d 次尝试后无法下载和解压 %s", maxRetries, url)
}

// downloadAndExtractOnce 方法负责单次下载和解压文件
func (d *Downloader) downloadAndExtractOnce(url string) error {
	resp, err := d.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 提取文件名
	filename := filepath.Base(url)

	// 创建临时目录
	tmpDir := filepath.Join(".", "temp")
	os.MkdirAll(tmpDir, os.ModePerm)

	// 创建tar.gz文件
	filePath := filepath.Join(tmpDir, filename)
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close() // 添加 defer 语句

	// 将HTTP响应体复制到文件
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	// 解压tar.gz文件
	fmt.Printf("正在解压 %s...\n", filePath)
	err = extract(filePath, tmpDir)
	if err != nil {
		return err
	}
	fmt.Printf("完成解压 %s\n", filePath)

	return nil
}

func extract(src, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()

		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case header == nil:
			continue
		}

		target := filepath.Join(dest, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			file, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(file, tarReader); err != nil {
				return err
			}
		}
	}
}

func findIPAddresses(rootDir string) (ipv4Addresses, ipv6Addresses []string, err error) {
	uniqueIPv4 := make(map[string]bool)
	uniqueIPv6 := make(map[string]bool)

	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		if strings.HasSuffix(path, ".csv") || strings.HasSuffix(path, ".txt") {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			re := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
			matches := re.FindAllString(string(content), -1)

			for _, match := range matches {
				if !isPrivateIP(match) {
					ipAddr := net.ParseIP(match)
					if ipAddr != nil {
						if ipAddr.To4() != nil {
							uniqueIPv4[ipAddr.String()] = true
						} else {
							uniqueIPv6[ipAddr.String()] = true
						}
					}
				}
			}
		}

		return nil
	})

	for ipv4 := range uniqueIPv4 {
		ipv4Addresses = append(ipv4Addresses, ipv4)
	}
	for ipv6 := range uniqueIPv6 {
		ipv6Addresses = append(ipv6Addresses, ipv6)
	}

	return ipv4Addresses, ipv6Addresses, err
}

func isPrivateIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	return ipAddr != nil && (ipAddr.IsLoopback() || ipAddr.IsLinkLocalUnicast() || ipAddr.IsLinkLocalMulticast() ||
		ipAddr.IsUnspecified() || (ipAddr.To4() != nil && ipAddr.IsPrivate()))
}

func parseCloudflareIPs(version string) ([]string, error) {
	url := fmt.Sprintf("https://www.cloudflare.com/ips-%s", version)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cidr := strings.Split(string(body), "\n")
	// 移除空行
	var cleanedIPs []string
	for _, ip := range cidr {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			ipRanges, err := generateRandomIPRange(ip)
			if err != nil {
				return nil, fmt.Errorf("error generating IP range: %v", err)
			}
			cleanedIPs = append(cleanedIPs, ipRanges...)
		}
	}

	return cleanedIPs, nil
}

// generateRandomIPRange 方法负责生成带有随机最后一位的IP范围
func generateRandomIPRange(ipAddr string) ([]string, error) {
	var ips []string

	// 解析CIDR格式的IP地址
	_, ipNet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return nil, fmt.Errorf("无法解析CIDR格式的IP: %v", err)
	}

	// 循环遍历CIDR范围内的每个IP地址
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		// 将CIDR中的最后一个数字替换为随机数
		randomIP := replaceLastOctetWithRandom(ip)
		ips = append(ips, randomIP.String())
	}

	return ips, nil
}

// replaceLastOctetWithRandom 方法替换IP的最后一位为随机数
func replaceLastOctetWithRandom(ip net.IP) net.IP {
	// 复制IP地址以避免更改原始地址
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// 生成一个随机数替换最后一个数字
	newIP[len(newIP)-1] = byte(rand.Intn(256))

	return newIP
}

func UpdateConfig(configFile []byte, results []speedtestresult) error {
	// 创建字符串切片用于存储 IP 地址
	var ips []string

	// 从结果中获取 IP 地址并存储在 ips 中
	for _, res := range results {
		ips = append(ips, res.result.ip)
	}

	// 移除注释
	configString := removeComments(string(configFile))

	// 解析 JSON
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configString), &config); err != nil {
		return fmt.Errorf("JSON 解析失败: %v", err)
	}

	// 保存符合条件的服务器配置
	var savedServers []interface{}

	// 遍历服务器配置
	for _, server := range config["servers"].([]interface{}) {
		serverMap, ok := server.(map[string]interface{})
		if !ok {
			continue
		}

		// 检查必要字段是否存在
		disabled, _ := serverMap["disabled"].(bool)
		mode, _ := serverMap["mode"].(string)
		address, _ := serverMap["address"].(string) // 注意：这里修改了获取 IP 地址的方式
		port, _ := serverMap["port"].(float64)
		method, _ := serverMap["method"].(string)
		password, _ := serverMap["password"].(string)
		plugin, pluginExists := serverMap["plugin"].(string)
		pluginOpts, optsExists := serverMap["plugin_opts"].(string)

		// 记录获取的字段值
		log.Printf("disabled: %v, mode: %s, address: %s, port: %v, method: %s, password: %s, plugin: %s, pluginOpts: %s\n", disabled, mode, address, port, method, password, plugin, pluginOpts)

		// 只修改满足条件的服务器配置
		if strings.ToLower(plugin) == "v2ray-plugin" && !strings.Contains(strings.ToLower(pluginOpts), "quic") {
			// 获取ips数组中的IP地址
			serverMap["address"] = ips[len(savedServers)%len(ips)]
			// 移除 plugin 和 plugin_opts 项如果它们不存在于原始配置中
			if !pluginExists {
				delete(serverMap, "plugin")
			}
			if !optsExists {
				delete(serverMap, "plugin_opts")
			}
			savedServers = append(savedServers, serverMap)
		} else {
			// 不满足条件的服务器配置，直接添加到保存的服务器列表中，保持不变
			savedServers = append(savedServers, serverMap)
		}
	}

	// 更新服务器配置
	config["servers"] = savedServers

	// 转换为 JSON 字符串
	newConfig, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return fmt.Errorf("无法转换为 JSON 字符串: %v", err)
	}

	// 保存到文件
	if err := ioutil.WriteFile(*SSJson, newConfig, 0644); err != nil {
		return fmt.Errorf("无法写入配置文件: %v", err)
	}

	return nil
}

// removeComments 移除JSON字符串中的注释
func removeComments(jsonString string) string {
	lines := strings.Split(jsonString, "\n")
	var cleanedLines []string

	for _, line := range lines {
		// 移除行内注释
		line = strings.Split(line, "//")[0]
		// 移除行尾注释
		line = strings.Split(line, "#")[0]

		cleanedLines = append(cleanedLines, line)
	}

	return strings.Join(cleanedLines, "\n")
}
