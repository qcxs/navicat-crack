package main

import (
	"fmt"
	"os/exec"
)

// openNetworkPanel 打开 Windows 的「网络连接」面板，由用户在系统中自行操作网卡。
func openNetworkPanel() error {
	return exec.Command("control.exe", "ncpa.cpl").Start()
}

func onOpenNetworkPanel() {
	if err := openNetworkPanel(); err != nil {
		msgBox(hwndMain, fmt.Sprintf("打开网络连接面板失败：%v", err), "提示", mbIconError)
		return
	}
	appendLog("[完成] 已打开系统「网络连接」面板，可在其中右键网卡选择「禁用/启用」")
}
