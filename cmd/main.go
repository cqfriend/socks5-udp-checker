package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	version = "1.2.0"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	var (
		proxyFlag      string
		targetFlag     string
		ntpFlag        string
		dnsServerFlag  string
		stunServerFlag string
		modeFlag       string
		timeoutFlag    time.Duration
		debugFlag      bool
		dnsOnlyFlag    bool
		atypOnlyFlag   bool
		natOnlyFlag    bool
		ipOnlyFlag     bool
		versionFlag    bool
		helpFlag       bool
	)

	fs := flag.NewFlagSet("socks5-udp-checker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&proxyFlag, "proxy", "", "SOCKS5 proxy address")
	fs.StringVar(&targetFlag, "target", "", "NTP test server (default: ntp1.aliyun.com:123)")
	fs.StringVar(&ntpFlag, "ntp", "", "Alias for -target")
	fs.StringVar(&dnsServerFlag, "dns-server", "223.5.5.5:53", "DNS test server for UDP 53 testing")
	fs.StringVar(&stunServerFlag, "stun-server", "stun.miwifi.com:3478", "STUN test server for NAT type detection")
	fs.StringVar(&modeFlag, "mode", "all", "Detection mode: all, standard, uot-v1, uot-v2, uot, dns, atyp, nat, stun, ip")
	fs.DurationVar(&timeoutFlag, "timeout", 5*time.Second, "Connection and request timeout")
	fs.BoolVar(&debugFlag, "debug", false, "Enable verbose protocol debug logging")
	fs.BoolVar(&dnsOnlyFlag, "dns", false, "Enable DNS (UDP 53) detection mode")
	fs.BoolVar(&atypOnlyFlag, "atyp", false, "Enable ATYP domain vs IPv4 resolution check")
	fs.BoolVar(&natOnlyFlag, "nat", false, "Enable NAT type detection (STUN)")
	fs.BoolVar(&natOnlyFlag, "stun", false, "Alias for -nat")
	fs.BoolVar(&ipOnlyFlag, "ip", false, "Only query and output proxy exit IP")
	fs.BoolVar(&versionFlag, "version", false, "Show version information")
	fs.BoolVar(&versionFlag, "v", false, "Alias for -version")
	fs.BoolVar(&helpFlag, "help", false, "Show usage help")
	fs.BoolVar(&helpFlag, "h", false, "Alias for -help")

	fs.Usage = printUsage

	reorderedArgs, positionalArgs := splitFlagsAndPositional(os.Args[1:])
	if err := fs.Parse(reorderedArgs); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if helpFlag {
		printUsage()
		os.Exit(0)
	}

	if versionFlag {
		fmt.Printf("SOCKS5 UDP & UoT Checker v%s (commit: %s, built: %s by %s)\n", version, commit, date, builtBy)
		os.Exit(0)
	}

	if proxyFlag == "" && len(positionalArgs) > 0 {
		proxyFlag = positionalArgs[0]
	}

	if proxyFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: proxy address is required (use -proxy <address> or pass as first argument).\n\n")
		printUsage()
		os.Exit(1)
	}

	targetServer := targetFlag
	if targetServer == "" {
		targetServer = ntpFlag
	}
	if targetServer == "" {
		targetServer = "ntp1.aliyun.com:123"
	}
	if !strings.Contains(targetServer, ":") {
		targetServer = netJoinPort(targetServer, "123")
	}

	if !strings.Contains(dnsServerFlag, ":") {
		dnsServerFlag = netJoinPort(dnsServerFlag, "53")
	}
	if !strings.Contains(stunServerFlag, ":") {
		stunServerFlag = netJoinPort(stunServerFlag, "3478")
	}

	cfg, err := parseSocks5String(proxyFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid proxy address format: %v\n", err)
		os.Exit(1)
	}

	debug := &DebugLogger{enabled: debugFlag}

	effectiveMode := strings.ToLower(modeFlag)
	if ipOnlyFlag {
		effectiveMode = "ip"
	} else if dnsOnlyFlag && effectiveMode == "all" {
		effectiveMode = "dns"
	} else if atypOnlyFlag && effectiveMode == "all" {
		effectiveMode = "atyp"
	} else if natOnlyFlag && effectiveMode == "all" {
		effectiveMode = "nat"
	}

	// If mode is ip only, just query and output exit IP directly
	if effectiveMode == "ip" {
		exitInfo, err := QueryProxyExitIP(cfg, timeoutFlag, debug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to query exit IP: %v\n", err)
			os.Exit(1)
		}
		locParts := formatLocation(exitInfo)
		if locParts != "" {
			fmt.Printf("%s (%s)\n", exitInfo.IP, locParts)
		} else {
			fmt.Println(exitInfo.IP)
		}
		os.Exit(0)
	}

	fmt.Println("==================================================")
	fmt.Println("         SOCKS5 UDP & UoT Checker")
	fmt.Println("==================================================")
	maskedProxy := maskPassword(cfg)
	fmt.Printf("Proxy:       %s\n", maskedProxy)

	// Query Proxy Exit IP
	exitInfo, exitErr := QueryProxyExitIP(cfg, timeoutFlag, debug)
	var exitLocStr string
	if exitErr == nil && exitInfo != nil {
		loc := formatLocation(exitInfo)
		if loc != "" {
			exitLocStr = fmt.Sprintf(" (%s)", loc)
		}
		fmt.Printf("Exit IP:     \033[32m%s\033[0m%s\n", exitInfo.IP, exitLocStr)
	} else {
		fmt.Printf("Exit IP:     \033[33m[Query Failed: %v]\033[0m\n", exitErr)
	}

	fmt.Printf("NTP Target:  %s\n", targetServer)
	if effectiveMode == "all" || effectiveMode == "dns" {
		fmt.Printf("DNS Target:  %s\n", dnsServerFlag)
	}
	if effectiveMode == "all" || effectiveMode == "nat" || effectiveMode == "stun" {
		fmt.Printf("STUN Target: %s\n", stunServerFlag)
	}
	fmt.Printf("Mode:        %s\n", effectiveMode)
	fmt.Printf("Timeout:     %v\n", timeoutFlag)
	if debugFlag {
		fmt.Printf("Debug:       enabled\n")
	}
	fmt.Println("--------------------------------------------------")

	type testItem struct {
		title string
		run   func() (bool, string, string)
	}

	var items []testItem

	// 1. Standard UDP (NTP 123)
	if effectiveMode == "all" || effectiveMode == "standard" || effectiveMode == "socks5" {
		items = append(items, testItem{
			title: "Standard SOCKS5 UDP (NTP Port 123)",
			run: func() (bool, string, string) {
				res, err := TestStandardUDP(cfg, targetServer, timeoutFlag, debug)
				if err == nil && res.Success {
					details := fmt.Sprintf("RTT: %v | Stratum: %d | Offset: %v | Time: %s",
						res.RTT.Round(time.Microsecond), res.Stratum, res.Offset.Round(time.Microsecond), res.Time.Format("15:04:05 MST"))
					return true, "SUPPORTED", details
				}
				return false, "NOT SUPPORTED", fmt.Sprintf("Error: %v", res.Error)
			},
		})
	}

	// 2. DNS Query (UDP 53)
	if effectiveMode == "all" || effectiveMode == "dns" {
		items = append(items, testItem{
			title: fmt.Sprintf("DNS Resolution (UDP Port 53 -> %s)", dnsServerFlag),
			run: func() (bool, string, string) {
				res, err := TestDNSQuery(cfg, dnsServerFlag, timeoutFlag, debug)
				if err == nil && res.Success {
					details := fmt.Sprintf("RTT: %v | Query: one.one.one.one -> %s",
						res.RTT.Round(time.Microsecond), res.ResolvedIP)
					return true, "SUPPORTED", details
				}
				return false, "NOT SUPPORTED", fmt.Sprintf("Error: %v", res.Error)
			},
		})
	}

	// 3. ATYP Remote Domain Resolution
	if effectiveMode == "all" || effectiveMode == "atyp" {
		items = append(items, testItem{
			title: "ATYP Remote Domain Resolution (FQDN 0x03 vs IPv4 0x01)",
			run: func() (bool, string, string) {
				res, err := TestATYPResolution(cfg, targetServer, timeoutFlag, debug)
				if err != nil {
					return false, "NOT SUPPORTED", fmt.Sprintf("Error: %v", err)
				}
				ipStatus := "Failed"
				if res.IPSupported {
					ipStatus = fmt.Sprintf("Supported (%v)", res.IPRTT.Round(time.Microsecond))
				}
				domainStatus := "Failed"
				if res.DomainSupported {
					domainStatus = fmt.Sprintf("Supported (%v)", res.DomainRTT.Round(time.Microsecond))
				}

				details := fmt.Sprintf("IPv4 (0x01): %s | Domain (0x03): %s\n      Note: %s",
					ipStatus, domainStatus, res.Details)

				if res.DomainSupported {
					return true, "SUPPORTED (Full Remote DNS)", details
				} else if res.IPSupported {
					return false, "PARTIAL (IPv4 Only, No Remote DNS)", details
				}
				return false, "NOT SUPPORTED", details
			},
		})
	}

	// 4. UDP-over-TCP v1
	if effectiveMode == "all" || effectiveMode == "uot-v1" || effectiveMode == "v1" || effectiveMode == "uot1" || effectiveMode == "uot" {
		items = append(items, testItem{
			title: "UDP-over-TCP v1 (sp.udp-over-tcp.arpa)",
			run: func() (bool, string, string) {
				res, err := TestUoTv1(cfg, targetServer, timeoutFlag, debug)
				if err == nil && res.Success {
					details := fmt.Sprintf("RTT: %v | Stratum: %d | Offset: %v",
						res.RTT.Round(time.Microsecond), res.Stratum, res.Offset.Round(time.Microsecond))
					return true, "SUPPORTED", details
				}
				return false, "NOT SUPPORTED", fmt.Sprintf("Error: %v", res.Error)
			},
		})
	}

	// 5. UDP-over-TCP v2
	if effectiveMode == "all" || effectiveMode == "uot-v2" || effectiveMode == "v2" || effectiveMode == "uot2" || effectiveMode == "uot" {
		items = append(items, testItem{
			title: "UDP-over-TCP v2 (sp.v2.udp-over-tcp.arpa)",
			run: func() (bool, string, string) {
				res, err := TestUoTv2(cfg, targetServer, timeoutFlag, debug)
				if err == nil && res.Success {
					details := fmt.Sprintf("RTT: %v | Stratum: %d | Offset: %v",
						res.RTT.Round(time.Microsecond), res.Stratum, res.Offset.Round(time.Microsecond))
					return true, "SUPPORTED", details
				}
				return false, "NOT SUPPORTED", fmt.Sprintf("Error: %v", res.Error)
			},
		})
	}

	// 6. NAT Type Detection (STUN)
	if effectiveMode == "all" || effectiveMode == "nat" || effectiveMode == "stun" {
		items = append(items, testItem{
			title: fmt.Sprintf("NAT Type Detection (STUN: %s)", stunServerFlag),
			run: func() (bool, string, string) {
				res, err := TestNATType(cfg, stunServerFlag, timeoutFlag, debug)
				if err == nil && res.Success {
					details := fmt.Sprintf("Type: %s | Mapped Endpoint: %s:%d\n      Behavior: %s",
						res.NATType, res.MappedIP, res.MappedPort, res.Details)
					return true, res.NATType, details
				}
				return false, "NOT SUPPORTED / TIMEOUT", fmt.Sprintf("Error: %v", res.Error)
			},
		})
	}

	type summaryEntry struct {
		title   string
		status  string
		success bool
	}
	var summaries []summaryEntry
	hasSuccess := false

	for i, item := range items {
		fmt.Printf("[%d/%d] %s:\n", i+1, len(items), item.title)
		ok, status, detail := item.run()
		if ok {
			hasSuccess = true
			fmt.Printf("      Status:  \033[32m[SUCCESS]\033[0m %s\n", status)
		} else {
			fmt.Printf("      Status:  \033[31m[FAILED]\033[0m %s\n", status)
		}
		if detail != "" {
			fmt.Printf("      Detail:  %s\n", detail)
		}
		fmt.Println()

		cleanTitle := item.title
		if parenIdx := strings.Index(cleanTitle, "("); parenIdx != -1 {
			cleanTitle = strings.TrimSpace(cleanTitle[:parenIdx])
		}
		summaries = append(summaries, summaryEntry{
			title:   cleanTitle,
			status:  status,
			success: ok,
		})
	}

	fmt.Println("==================================================")
	fmt.Println("Summary:")
	if exitInfo != nil && exitInfo.IP != "" {
		fmt.Printf("  • Proxy Outbound Exit IP          : \033[32m%s\033[0m%s\n", exitInfo.IP, exitLocStr)
	} else {
		fmt.Printf("  • Proxy Outbound Exit IP          : \033[31mUNREACHABLE / TIMEOUT\033[0m\n")
	}

	for _, s := range summaries {
		if s.success {
			fmt.Printf("  • %-32s: \033[32m%s\033[0m\n", s.title, s.status)
		} else {
			fmt.Printf("  • %-32s: \033[31m%s\033[0m\n", s.title, s.status)
		}
	}
	fmt.Println("==================================================")

	if !hasSuccess {
		os.Exit(1)
	}
	os.Exit(0)
}

func formatLocation(info *ProxyExitInfo) string {
	if info == nil {
		return ""
	}
	var parts []string
	if info.Country != "" {
		parts = append(parts, info.Country)
	}
	if info.Region != "" && info.Region != info.Country {
		parts = append(parts, info.Region)
	}
	if info.City != "" && info.City != info.Region {
		parts = append(parts, info.City)
	}
	if info.ISP != "" {
		parts = append(parts, info.ISP)
	}
	return strings.Join(parts, ", ")
}

func splitFlagsAndPositional(args []string) ([]string, []string) {
	flagsWithValues := map[string]bool{
		"-proxy": true, "--proxy": true,
		"-target": true, "--target": true,
		"-ntp": true, "--ntp": true,
		"-dns-server": true, "--dns-server": true,
		"-stun-server": true, "--stun-server": true,
		"-mode": true, "--mode": true,
		"-timeout": true, "--timeout": true,
	}

	var flagArgs []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			cleanFlag := arg
			if eqIdx := strings.Index(cleanFlag, "="); eqIdx != -1 {
				cleanFlag = cleanFlag[:eqIdx]
			} else if flagsWithValues[cleanFlag] && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positional = append(positional, arg)
		}
	}

	return flagArgs, positional
}

func netJoinPort(host, port string) string {
	return fmt.Sprintf("%s:%s", host, port)
}

func maskPassword(cfg socks5Config) string {
	if cfg.username == "" && cfg.password == "" {
		return cfg.address
	}
	pass := ""
	if cfg.password != "" {
		pass = ":******"
	}
	return fmt.Sprintf("%s%s@%s", cfg.username, pass, cfg.address)
}

func printUsage() {
	fmt.Println(`SOCKS5 UDP & UoT (UDP-over-TCP) Checker

Usage:
  socks5-udp-checker -proxy <proxy> [options]
  socks5-udp-checker <proxy> [options]

Proxy Formats:
  • username:password@host:port
  • socks5://username:password@host:port
  • host:port:username:password
  • socks5://host:port:username:password
  • socks5:host:port:username:password
  • host:port
  • socks5://host:port
  • socks5:host:port

Options:
  -proxy <string>        SOCKS5 proxy address
  -target <string>       NTP test server (default: "ntp1.aliyun.com:123")
  -ntp <string>          Alias for -target
  -dns-server <string>   DNS server for UDP 53 testing (default: "223.5.5.5:53")
  -stun-server <string>  STUN server for NAT type testing (default: "stun.miwifi.com:3478")
  -mode <string>         Test mode: all, standard, uot-v1, uot-v2, uot, dns, atyp, nat, stun, ip (default: "all")
  -ip                    Only query and print proxy real exit IP
  -dns                   Test DNS resolution on UDP port 53
  -atyp                  Test ATYP remote domain vs IPv4 resolution in UDP datagrams
  -nat, -stun            Test NAT type classification (Full Cone / Symmetric / Restricted)
  -timeout <dur>         Connection timeout (default: 5s)
  -debug                 Print step-by-step protocol debug logs
  -v, -version           Show version information
  -h, -help              Show this help message

Examples:
  socks5-udp-checker -proxy 127.0.0.1:1080
  socks5-udp-checker -proxy user:pass@127.0.0.1:1080 -ip
  socks5-udp-checker -proxy user:pass@127.0.0.1:1080 -dns
  socks5-udp-checker -proxy 127.0.0.1:1080 -nat
  socks5-udp-checker -proxy 127.0.0.1:1080:user:pass -mode all -debug`)
}
