// Package ui 实现 bubbletea 驱动的 TUI 选项卡交互菜单。
package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// 主题色
var (
	colorAccent    = lipgloss.Color("57")   // teal
	colorSubtle    = lipgloss.Color("240")  // gray
	colorError     = lipgloss.Color("196")  // red
	colorSuccess   = lipgloss.Color("82")   // green
	colorHighlight = lipgloss.Color("205")  // magenta
)

// Handler 处理一次解密请求，返回日志行与错误。
type Handler func(path, mode string) ([]string, error)

// App 是 TUI 应用。
type App struct {
	// tab 当前选中的选项卡
	tab int
	// steps: 0=选择模式, 1=输入固件, 2=确认解密, 3=结果
	step int

	// fileInput 固件路径输入框
	fileInput textinput.Model

	// modeList 模式列表（Tab 对应的选项卡内容）
	modeList list.Model

	// handle 实际解密处理器
	handle Handler

	// 计算结果
	inputPath string
	outputLog []string
	statusMsg string
	statusOK  bool
	modeName  string

	width  int
	height int
}

// Tab 定义
type tabDef struct {
	title string
	desc  string
}

var tabs = []tabDef{
	{"解密固件", "自动检测固件类型并解密（RSA-PSS + AES-CBC / DES-CBC）"},
	{"密钥信息", "查看内置的 RSA-2048 与 DES 公钥/密钥信息"},
	{"关于", "工具版本、来源与授权信息"},
}

var modeItems = []list.Item{
	modeItem{name: "自动检测", desc: "根据文件头自动识别 fw-type / Tapo / Switch 并解密", active: true},
	modeItem{name: "强制 fw-type", desc: "强制按 fw-type: 路由器/AP 固件处理（RSA_KEY=RSA1）"},
	modeItem{name: "强制 Tapo", desc: "强制按 Tapo/IPC 摄像头固件处理（RSA_KEY=RSA0）"},
	modeItem{name: "强制 Switch", desc: "强制按 Omada 交换机固件处理（DES-CBC）"},
}

type modeItem struct {
	name   string
	desc   string
	active bool
}

func (m modeItem) Title() string { return m.name }
func (m modeItem) Description() string { return m.desc }
func (m modeItem) FilterValue() string { return m.name + " " + m.desc }

// New 创建 TUI 应用。handler 用于执行真实的固件解密。
func New(handler Handler) *App {
	ti := textinput.New()
	ti.Placeholder = "拖入或输入固件文件路径（如 Tapo_C210v2.bin）"
	ti.Focus()
	ti.CharLimit = 512
	ti.Width = 60

	li := list.New(modeItems, list.NewDefaultDelegate(), 0, 0)
	li.Title = "选择解密模式"
	li.SetShowStatusBar(false)
	li.SetFilteringEnabled(false)

	return &App{
		step:     0,
		fileInput: ti,
		modeList:  li,
		handle:    handler,
	}
}

func (a *App) Init() tea.Cmd {
	return textinput.Blink
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.modeList.SetSize(msg.Width, msg.Height/2)
		return a, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return a, tea.Quit
		}

		// 在确认/结果界面按 esc 或 enter 返回
		if a.step == 2 {
			switch msg.String() {
			case "esc":
				a.step = 1
				return a, nil
			case "enter":
				a.runDecrypt()
				return a, nil
			}
			return a, nil
		}
		if a.step == 3 {
			switch msg.String() {
			case "esc", "enter":
				a.step = 0
				return a, nil
			}
			return a, nil
		}
		if a.step == 1 {
			switch msg.String() {
			case "enter":
				a.inputPath = strings.TrimSpace(a.fileInput.Value())
				if a.inputPath == "" {
					a.statusMsg = "请输入固件文件路径"
					a.statusOK = false
					return a, nil
				}
				if _, err := os.Stat(a.inputPath); err != nil {
					a.statusMsg = "文件不存在: " + a.inputPath
					a.statusOK = false
					return a, nil
				}
				a.statusMsg = ""
				a.step = 2
				return a, nil
			case "esc":
				a.step = 0
				a.statusMsg = ""
				return a, nil
			}
			var cmd tea.Cmd
			a.fileInput, cmd = a.fileInput.Update(msg)
			return a, cmd
		}

		// step 0: 选项卡 + 模式列表
		switch msg.String() {
		case "q":
			return a, tea.Quit
		case "tab", "shift+tab":
			if a.tab == 0 {
				a.tab = 1
			} else if a.tab == 1 {
				a.tab = 2
			} else {
				a.tab = 0
			}
			return a, nil
		case "left":
			a.tab = (a.tab + 2) % 3
			return a, nil
		case "right":
			a.tab = (a.tab + 1) % 3
			return a, nil
		case "enter":
			// Tab 2（关于）无交互，Tab 0 进入下一步
			if a.tab == 0 {
				a.step = 1
				return a, nil
			}
			return a, nil
		case "up", "down", "k", "j":
			if a.tab == 0 {
				var cmd tea.Cmd
				a.modeList, cmd = a.modeList.Update(msg)
				return a, cmd
			}
			return a, nil
		}
		return a, nil
	}

	return a, nil
}

func (a *App) View() string {
	var b strings.Builder
	b.WriteString(header())
	b.WriteString("\n\n")
	b.WriteString(a.tabBar())
	b.WriteString("\n\n")

	switch a.step {
	case 0:
		b.WriteString(a.viewStep0())
	case 1:
		b.WriteString(a.viewStep1())
	case 2:
		b.WriteString(a.viewStep2())
	case 3:
		b.WriteString(a.viewStep3())
	}

	if a.statusMsg != "" {
		col := colorError
		if a.statusOK {
			col = colorSuccess
		}
		b.WriteString("\n\n" + lipgloss.NewStyle().Foreground(col).Bold(true).Render("● "+a.statusMsg))
	}

	b.WriteString("\n\n" + footer())
	return b.String()
}

func (a *App) tabBar() string {
	var items []string
	for i, t := range tabs {
		style := lipgloss.NewStyle().Padding(0, 2).Foreground(colorSubtle)
		if i == a.tab {
			style = lipgloss.NewStyle().
				Padding(0, 2).
				Foreground(lipgloss.Color("0")).
				Background(colorAccent).
				Bold(true)
		}
		items = append(items, style.Render(t.title))
	}
	bar := lipgloss.JoinHorizontal(lipgloss.Left, items...)
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(colorAccent).
		Padding(0, 1).
		Render(bar)
}

func (a *App) viewStep0() string {
	switch a.tab {
	case 0:
		desc := fmt.Sprintf("使用模式：%s\n请按 [Enter] 继续，输入固件路径。", a.selectedModeName())
		return a.modeList.View() + "\n\n" + lipgloss.NewStyle().Foreground(colorSubtle).Render(desc) +
			"\n\n" + lipgloss.NewStyle().Foreground(colorAccent).Render("[Enter] 下一步   [Tab/←/→] 切换选项卡")
	case 1:
		var b strings.Builder
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render("内置密钥信息\n\n"))
		b.WriteString(lipgloss.NewStyle().Foreground(colorSubtle).Render(
			"以下密钥已由 extract_keys.sh 从官方固件中提取，\n" +
				"并经 SHA256 校验（0a7857d4...b6e64）确认一致。\n\n"))
		b.WriteString(fmt.Sprintf("RSA_0 (Tapo/IPC)   : %d 位公钥\n", 2048))
		b.WriteString(fmt.Sprintf("RSA_1 (fw-type)    : %d 位公钥\n", 2048))
		b.WriteString("DES_KEY            : 0001020304050607\n")
		b.WriteString("DES_IV             : f51010736efbabb2\n")
		b.WriteString("\n返回请按 [Tab]\n")
		return b.String()
	default:
		return lipgloss.NewStyle().Foreground(colorSubtle).Render(
			"TP-Link 固件解密工具 (Go 重构版)\n\n"+
				"原 C 版本作者: Watchful_IP & robbins\n"+
				"链接: watchfulip.github.io\n\n"+
				"功能:\n"+
				"  · fw-type 路由器/AP 固件 RSA-PSS 验签 + AES-128-CBC 解密\n"+
				"  · Tapo/IPC 摄像头固件 RSA-PSS 验签 + AES-128-CBC 解密\n"+
				"  · Omada 交换机固件 DES-CBC 解密\n\n"+
				"按 [Tab] 返回\n")
	}
}

func (a *App) viewStep1() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render("输入固件文件\n\n"))
	b.WriteString("模式：" + a.selectedModeName() + "\n\n")
	b.WriteString(a.fileInput.View())
	b.WriteString("\n\n" + lipgloss.NewStyle().Foreground(colorSubtle).Render("[Enter] 确认   [Esc] 返回"))
	return b.String()
}

func (a *App) viewStep2() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render("确认解密\n\n"))
	b.WriteString("固件文件：" + a.inputPath + "\n")
	b.WriteString("解密模式：" + a.selectedModeName() + "\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorSubtle).Render("将输出 <文件名>.dec 到同目录。"))
	b.WriteString("\n\n" + lipgloss.NewStyle().Foreground(colorHighlight).Render("[Enter] 开始解密   [Esc] 返回"))
	return b.String()
}

func (a *App) viewStep3() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render("解密完成\n\n"))
	for _, l := range a.outputLog {
		b.WriteString(l + "\n")
	}
	b.WriteString("\n" + lipgloss.NewStyle().Foreground(colorSubtle).Render("[Enter] 返回"))
	return b.String()
}

func (a *App) selectedModeName() string {
	sel, ok := a.modeList.SelectedItem().(modeItem)
	if !ok {
		return ""
	}
	return sel.name
}

func (a *App) runDecrypt() {
	a.outputLog = nil
	a.statusMsg = ""
	a.statusOK = true
	a.modeName = a.selectedModeName()

	// 调用注入的真实解密处理器。
	logs, err := a.handle(a.inputPath, a.modeName)
	if err != nil {
		a.statusOK = false
		a.statusMsg = "解密失败: " + err.Error()
	}
	a.outputLog = logs
	a.step = 3
}

func header() string {
	return lipgloss.NewStyle().
		Foreground(colorAccent).
		Bold(true).
		Render("◆ TP-Link 固件解密工具 (Go)")
}

func footer() string {
	return lipgloss.NewStyle().Foreground(colorSubtle).Render(
		"Tab 切换选项卡   Enter 确认   Esc 返回   q/Ctrl+C 退出")
}
