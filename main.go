package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	timeout     = 1000 * time.Millisecond // 超时时间
	maxDuration = 2500 * time.Millisecond // 最大持续时间
)

var (
	File         = flag.String("file", "ip.txt", "IP地址文件名称,格式为 ip port ,就是IP和端口之间用空格隔开")  // IP地址文件名称
	outFile      = flag.String("outfile", "ip.csv", "输出文件名称")                             // 输出文件名称
	maxThreads   = flag.Int("max", 20, "并发请求最大协程数")                                      // 最大协程数
	speedTest    = flag.Int("speedtest", 0, "下载测速协程数量,设为0禁用测速")                          // 下载测速协程数量
	speedTestURL = flag.String("url", "speed.bestip.one/__down?bytes=50000000", "测速文件地址") // 测速文件地址
	enableTLS    = flag.Bool("tls", false, "是否启用TLS")                                      // TLS是否启用
	TCPurl       = flag.String("tcpurl", "www.speedtest.net", "TCP请求地址")                  // TCP请求地址
)

type result struct {
	ip   string // IP地址
	port int    // 端口
	// host        string        // 主机名
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

// 尝试提升文件描述符的上限
func increaseMaxOpenFiles() {
	fmt.Println("正在尝试提升文件描述符的上限...")
	cmd := exec.Command("bash", "-c", "ulimit -n 10000")
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("提升文件描述符上限时出现错误: %v\n", err)
	} else {
		fmt.Printf("文件描述符上限已提升!\n")
	}
}
func ConvertToIP(cidrs string) ([]string, error) {
	var result []string
	ip, ipnet, err := net.ParseCIDR(cidrs)
	if err != nil {
		return nil, err
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		result = append(result, ip.String())
	}

	return result, nil
}
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func main() {
	flag.Parse()

	startTime := time.Now()
	osType := runtime.GOOS
	// 如果是linux系统,尝试提升文件描述符的上限
	// 判断是否以root用户运行

	if osType == "linux" && os.Getuid() == 0 {
		increaseMaxOpenFiles()
	}

	var locations []location
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在\n正在从 https://speed.bestip.one/locations 下载 locations.json")
		resp, err := http.Get("https://speed.bestip.one/locations")
		if err != nil {
			fmt.Printf("无法从URL中获取JSON: %v\n", err)
			return
		}

		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {

			}
		}(resp.Body)

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("无法读取响应体: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
		file, err := os.Create("locations.json")
		if err != nil {
			fmt.Printf("无法创建文件: %v\n", err)
			return
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {

			}
		}(file)

		_, err = file.Write(body)
		if err != nil {
			fmt.Printf("无法写入文件: %v\n", err)
			return
		}
	} else {
		fmt.Println("本地 locations.json 已存在,无需重新下载")
		fmt.Printf("information:\ntcpurl:%s\noutfile:%s\nfile:%s\n", *TCPurl, *outFile, *File)
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开文件: %v\n", err)
			return
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {

			}
		}(file)

		body, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("无法读取文件: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
	}

	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}

	ips, err := readIPs(*File)
	if err != nil {
		fmt.Printf("无法从文件中读取 IP: %v\n", err)
		return
	}

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

			parts := strings.Fields(ip)
			if len(parts) != 2 {
				fmt.Printf("IP地址格式错误: %s\n", ip)
				return
			}
			ipAddr := parts[0]
			portStr := parts[1]

			port, err := strconv.Atoi(portStr)
			if err != nil {
				fmt.Printf("端口格式错误: %s\n", portStr)
				return
			}

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ipAddr, strconv.Itoa(port)))
			if err != nil {
				return
			}
			defer func(conn net.Conn) {
				err := conn.Close()
				if err != nil {

				}
			}(conn)

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
			requestURL := protocol + *TCPurl + "/cdn-cgi/trace"

			req, _ := http.NewRequest("GET", requestURL, nil)

			// 添加用户代理
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")
			req.Close = true
			// 使用context设置超时时间
			ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
			defer cancel()

			req = req.WithContext(ctx)

			resp, err := client.Do(req)
			if err != nil {
				return
			}

			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {

				}
			}(resp.Body)
			duration := time.Since(start)
			if duration > maxDuration {
				return
			}
			// 使用io.ReadAll读取响应，并设置超时处理
			bodyCh := make(chan []byte, 1)
			go func() {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Println(err)
					return
				}
				bodyCh <- body
			}()
			select {
			case body := <-bodyCh:
				if strings.Contains(string(body), "uag=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36") {
					if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(string(body)); len(matches) > 1 {
						dataCenter := matches[1]
						loc, ok := locationMap[dataCenter]
						if ok {
							fmt.Printf("发现有效IP %s 端口 %d 位置信息 %s 延迟 %d 毫秒\n", ipAddr, port, loc.City, tcpDuration.Milliseconds())
							resultChan <- result{ipAddr, port, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration}
						} else {
							fmt.Printf("发现有效IP %s 端口 %d 位置信息未知 延迟 %d 毫秒\n", ipAddr, port, tcpDuration.Milliseconds())
							resultChan <- result{ipAddr, port, dataCenter, "", "", fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration}
						}
					}
				}
			case <-ctx.Done():
				//fmt.Println("Request timed out while reading response")
				return
			}

		}(ip)
	}

	wg.Wait()
	close(resultChan)

	if len(resultChan) == 0 {
		fmt.Println("没有发现有效的IP")
		return
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

					downloadSpeed := getDownloadSpeed(res.ip, res.port)
					results = append(results, speedtestresult{result: res, downloadSpeed: downloadSpeed})

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
		sort.Slice(results, func(i, j int) bool {
			return results[i].downloadSpeed > results[j].downloadSpeed
		})
	} else {
		sort.Slice(results, func(i, j int) bool {
			return results[i].result.tcpDuration < results[j].result.tcpDuration
		})
	}

	file, err := os.Create(*outFile)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	// 写入UTF-8 BOM
	_, err = file.WriteString("\xEF\xBB\xBF")
	if err != nil {
		return
	}
	writer := csv.NewWriter(file)
	if *speedTest > 0 {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市", "网络延迟", "下载速度"})
	} else {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市", "网络延迟"})
	}
	for _, res := range results {
		if *speedTest > 0 {
			downloadSpeedMBps := res.downloadSpeed / 1024 // 将下载速度从kB/s转换为MB/s
			writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.city, res.result.latency, fmt.Sprintf("%.2f MB/s", downloadSpeedMBps)})
		} else {
			writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.city, res.result.latency})
		}
	}
	writer.Flush()
	// 清除输出内容
	fmt.Print("\033[2J")
	fmt.Printf("成功将结果写入文件 %s，耗时 %d秒\n", *outFile, time.Since(startTime)/time.Second)
}

// 从文件中读取IP地址和端口
func readIPs(File string) ([]string, error) {
	file, err := os.Open(File)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) != 2 {
			fmt.Printf("行格式错误: %s\n", line)
			continue
		}
		ipAddr := parts[0]
		portStr := parts[1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			fmt.Printf("端口格式错误: %s\n", portStr)
			continue
		}
		//ipAddrs, err := ConvertToIP(ipAddr)
		//if err != nil {
		//	continue
		//}
		//for _, ipAddr := range ipAddrs {
		ip := fmt.Sprintf("%s %d", ipAddr, port)
		ips = append(ips, ip)
		//}
	}
	return ips, scanner.Err()
}

// 测速函数
func getDownloadSpeed(ip string, port int) float64 {
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
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return 0
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)

	fmt.Printf("正在测试IP %s 端口 %d\n", ip, port)
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
		fmt.Printf("IP %s 端口 %d 测速无效\n", ip, port)
		return 0
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	// 复制响应体到/dev/null，并计算下载速度
	written, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(startTime)
	speed := float64(written) / duration.Seconds() / 1024

	// 输出结果
	fmt.Printf("IP %s 端口 %d 下载速度 %.0f kB/s\n", ip, port, speed)
	return speed
}
