package control

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"strongbox/securefs"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	cfg "strongbox/configuration"
)

func ShowQuicDialog(a fyne.App, msg string, win fyne.Window) {
	q := dialog.NewConfirm("Quit", msg, func(_ bool) {
		a.Quit()
	}, win)
	q.SetDismissText("I Kown")
	q.SetConfirmText("Quit")
	q.Show()
}

func ShowPasswordDialog(win fyne.Window) {
	const leastPasswdLen = 3
	passwd := ""
	passwdEntry := widget.NewPasswordEntry()
	passwdEntry.Validator = func(input string) error {
		if len(input) < leastPasswdLen {
			return fmt.Errorf("must input least %d char", leastPasswdLen)
		}
		passwd = input
		return nil
	}
	passwdItem := &widget.FormItem{
		Text:   "Password",
		Widget: passwdEntry,
	}
	// passwdItem.Widget.Resize(fyne.NewSize(450, 300))

	items := []*widget.FormItem{passwdItem}
	d := dialog.NewForm("Input Password", "Submit", "Cancel", items, func(confirm bool) {
		if confirm {
			cfg.Cfg.SetPasswd(passwd)
		}
	}, win)

	d.Resize(fyne.NewSize(300, 180))
	d.Show()
}

func ShowListDialog(a fyne.App, win fyne.Window, listType int) {
	d := a.NewWindow("Process List")

	var listData []string
	switch listType {
	case 1:
		listData = make([]string, len(cfg.Cfg.Permission.AllowProcess))
		copy(listData[:], cfg.Cfg.Permission.AllowProcess[:])
	case 2:
		listData = make([]string, len(cfg.Cfg.Permission.DenyProcess))
		copy(listData[:], cfg.Cfg.Permission.DenyProcess[:])
	case 3:
		fps := securefs.GetForbidProcess()
		listData = make([]string, len(fps))
		copy(listData[:], fps[:])
	default:
		return
	}
	data := binding.BindStringList(
		&listData,
	)

	list := widget.NewListWithData(data,
		func() fyne.CanvasObject {
			itemInput := widget.NewEntry()
			itemSelect := widget.NewButton("...", func() {
				dlg := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
					if err == nil && dir != nil {
						log.Debug("item select:", dir.Path())
						// mountPointString.Set(dir.Path())
						itemInput.SetText(dir.Path())
					}
				}, d)
				dlg.Show()
			})
			itemDel := widget.NewButton("-", func() {
				oldList, err := data.Get()
				if err != nil {
					log.Error("get data failed:", err)
					return
				}
				for index, value := range oldList {
					if value == itemInput.Text {
						data.Set(append(oldList[0:index], oldList[index+1:]...))
					}
				}
			})

			addItemToWhite := widget.NewButton("Add To Whitelist", func() {
				if itemInput.Text == "" {
					log.Error("add empty to white list")
					info := dialog.NewInformation("Error", "cannot add empty to whitelist", d)
					info.Resize(fyne.NewSize(310, 180))
					info.Show()
					return
				}
				cfg.Cfg.Permission.AllowProcess = append(cfg.Cfg.Permission.AllowProcess, itemInput.Text)
				info := dialog.NewInformation("Tips", "add proccess to whitelist success", d)
				info.Resize(fyne.NewSize(310, 180))
				info.Show()
			})

			var itemButtons *fyne.Container = nil
			if listType != 3 {
				itemButtons = container.NewHBox(itemSelect, itemDel)
			} else {
				itemButtons = container.NewHBox(addItemToWhite)
			}
			itemRow := container.NewBorder(nil, nil, nil, itemButtons, itemInput)

			return itemRow
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			c := o.(*fyne.Container)
			c.Objects[0].(*widget.Entry).Bind(i.(binding.String))
		})

	var bottom *fyne.Container = nil

	add := widget.NewButton("Add", func() {
		val := ""
		data.Append(val)
	})
	cancel := widget.NewButton("Close", func() {
		d.Close()
	})
	save := widget.NewButton("Save", func() {
		listData, err := data.Get()
		if err != nil {
			return
		}
		switch listType {
		case 1:
			cfg.Cfg.Permission.AllowProcess = listData
		case 2:
			cfg.Cfg.Permission.DenyProcess = listData
		case 3:
		default:
			return
		}
		d.Close()
	})

	if listType != 3 {
		bottom = container.NewVBox(
			add,
			cancel,
			save,
		)
	} else {
		bottom = container.NewVBox(
			cancel,
		)
	}

	d.SetContent(container.NewBorder(nil, bottom, nil, nil, list))
	d.Resize(fyne.NewSize(650, 480))
	d.Show()
}

func RunStrongBoxApp() {
	a := app.New()

	defer GetControl().Unmount()

	win := a.NewWindow("StrongBox")

	if desk, ok := a.(desktop.App); ok {
		m := fyne.NewMenu("StrongBoxTray",
			fyne.NewMenuItem("Show", func() {
				win.Show()
			}))
		desk.SetSystemTrayMenu(m)
	}

	// mount point config
	mountPointString := binding.NewString()
	mountPointString.Set(cfg.Cfg.MountPoint)
	mountPointInput := widget.NewEntryWithData(mountPointString)
	mountPointInput.SetPlaceHolder("Enter MountPoint...")
	mountPointSelect := widget.NewButton("...", func() {
		dlg := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
			if err == nil && dir != nil {
				log.Debug("mount point select:", dir.Path())
				mountPointString.Set(dir.Path())
				cfg.Cfg.MountPoint = dir.Path()
			}
		}, win)
		dlg.Show()
	})
	mountRow := container.NewBorder(nil, nil, nil, mountPointSelect, mountPointInput)

	// backup config
	backupString := binding.NewString()
	backupString.Set(cfg.Cfg.Backup.Path)
	backupInput := widget.NewEntryWithData(backupString)
	backupInput.SetPlaceHolder("Enter Backup Path...")
	backupSelect := widget.NewButton("...", func() {
		dlg := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
			if err == nil && dir != nil {
				log.Debug("backup select:", dir.Path())
				backupString.Set(dir.Path())
				cfg.Cfg.Backup.Path = dir.Path()
			}
		}, win)
		dlg.Show()
	})
	backupRow := container.NewBorder(nil, nil, nil, backupSelect, backupInput)

	// backup memory
	backupMemoryCheck := widget.NewCheck("Use Memory Backup", func(value bool) {
		log.Println("backup memory check set to ", value)
		cfg.Cfg.Backup.Memory = value
		if value {
			backupInput.Disable()
		} else {
			backupInput.Enable()
		}
	})
	backupMemoryCheck.SetChecked(cfg.Cfg.Backup.Memory)

	// permission
	allowlist := widget.NewButton("Show Process Whitelist", func() {
		ShowListDialog(a, win, 1)
	})
	denylist := widget.NewButton("Show Process Blacklist", func() {
		ShowListDialog(a, win, 2)
	})
	blockedlist := widget.NewButton("Show Blocked Process", func() {
		ShowListDialog(a, win, 3)
	})

	// action
	saveButton := widget.NewButton("Save Config", func() {
		cfg.Cfg.Save()
	})
	mountButton := widget.NewButton("Mount", nil)
	mountButton.OnTapped = func() {
		if !GetControl().Running() {
			err := GetControl().Mount()
			if err != nil {
				d := dialog.NewInformation("Mount Failed", err.Error(), win)
				d.Resize(fyne.NewSize(310, 180))
				d.Show()
			} else {
				mountButton.SetText("Unmount")
				go GetControl().Wait()
				win.Hide()
			}
		} else {
			GetControl().Unmount()
			mountButton.SetText("Mount")
		}
	}
	submitRow := container.New(layout.NewGridLayout(2), saveButton, mountButton)

	form := &widget.Form{
		Items: []*widget.FormItem{ // we can specify items in the constructor
			{Text: "Mount Point", Widget: mountRow},
			{Text: "Backup Memory", Widget: backupMemoryCheck},
			{Text: "Backup", Widget: backupRow},
			{Text: "Whitelist", Widget: allowlist},
			{Text: "Blacklist", Widget: denylist},
			{Text: "Blockedlist", Widget: blockedlist},
			{Text: "", Widget: submitRow},
		},
	}

	// form.Append("Mount Point", mountRow)
	// form.Append("Whitelist", whitelist)

	// ttt := container.NewBorder(nil, nil, nil, widget.NewButton("+", nil), widget.NewLabel("item x.y"))
	// form.Append("MM", ttt)

	content := container.NewVBox(form)

	win.SetContent(content)
	win.SetCloseIntercept(func() {
		win.Hide()
	})

	win.Resize(fyne.NewSize(650, 480))

	ShowPasswordDialog(win)

	win.ShowAndRun()
}
