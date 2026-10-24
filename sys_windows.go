//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const taskName = "StreamHub"

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return filepath.Dir(p)
}

// config.json stă lângă streamhub.exe
func defaultConfigPath() string { return filepath.Join(exeDir(), "config.json") }

func setUDPSockOpts(fd uintptr, ttl int, setIf bool, ifIP [4]byte) {
	h := syscall.Handle(fd)
	const ipTTL = 4 // IP_TTL în Winsock
	syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttl)
	syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipTTL, ttl)
	syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4<<20)
	if setIf {
		syscall.SetsockoptInet4Addr(h, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, ifIP)
	}
}

// fără fereastră de consolă pentru ffmpeg
func childProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// ffmpeg.exe / srt-live-transmit.exe pot sta lângă streamhub.exe
// + jurnal în streamhub.log (util când rulează în fundal, fără consolă)
func platformInit() {
	dir := exeDir()
	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	lp := filepath.Join(dir, "streamhub.log")
	if fi, err := os.Stat(lp); err == nil && fi.Size() > 20<<20 {
		os.Rename(lp, lp+".old")
	}
	if f, err := os.OpenFile(lp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}
	log.Printf("folderul aplicației: %s", dir)
}

func openBrowser(url string) {
	exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// fatal: la dublu-click fereastra nu se închide înainte să poți citi eroarea
func fatal(err error) {
	log.Print("EROARE: ", err)
	fmt.Print("\nApasă Enter pentru a închide…")
	bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(1)
}

func isAdmin() bool {
	return exec.Command("net", "session").Run() == nil
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func powershell(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// -install: task programat care pornește StreamHub la boot (ca SYSTEM), fără limită de timp,
// repornit automat dacă se oprește; plus regulă în firewall.
// -uninstall: le elimină.
func platformService(install bool, cfgPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cfgAbs, _ := filepath.Abs(cfgPath)
	if !isAdmin() {
		arg := "-uninstall"
		if install {
			arg = "-install"
		}
		fmt.Println("Cer drepturi de Administrator…")
		_, err := powershell(fmt.Sprintf("Start-Process -FilePath %s -ArgumentList %s -Verb RunAs",
			psQuote(exe), psQuote(arg+` -config "`+cfgAbs+`"`)))
		if err != nil {
			return fmt.Errorf("nu am primit drepturi de Administrator")
		}
		return nil
	}
	defer func() {
		fmt.Print("\nApasă Enter pentru a închide…")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}()
	// oprește și șterge ce exista
	powershell(fmt.Sprintf("Stop-ScheduledTask -TaskName %s -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName %s -Confirm:$false -ErrorAction SilentlyContinue", psQuote(taskName), psQuote(taskName)))
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+taskName).Run()
	if !install {
		fmt.Println("StreamHub a fost oprit și eliminat de la pornirea automată.")
		return nil
	}
	script := fmt.Sprintf(`$a = New-ScheduledTaskAction -Execute %s -Argument %s -WorkingDirectory %s
$t = New-ScheduledTaskTrigger -AtStartup
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName %s -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
Start-ScheduledTask -TaskName %s`,
		psQuote(exe), psQuote(`-config "`+cfgAbs+`"`), psQuote(filepath.Dir(exe)), psQuote(taskName), psQuote(taskName))
	if out, err := powershell(script); err != nil {
		return fmt.Errorf("nu am putut crea pornirea automată: %v\n%s", err, out)
	}
	if out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+taskName,
		"dir=in", "action=allow", "program="+exe, "enable=yes", "profile=any").CombinedOutput(); err != nil {
		fmt.Printf("Atenție: regula de firewall nu a fost adăugată: %s\n", strings.TrimSpace(string(out)))
	}
	fmt.Println("StreamHub rulează acum în fundal și pornește automat odată cu Windows.")
	fmt.Println("Config:", cfgAbs)
	fmt.Println("Panou:  http://127.0.0.1:4000/  (sau portul din config)")
	fmt.Println("Pentru oprire definitivă: streamhub.exe -uninstall")
	return nil
}
