package control

import (
	"fmt"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func ShowQuicDialog(a fyne.App, msg string, win fyne.Window) {
	q := dialog.NewConfirm("Quit", msg, func(_ bool) {
		a.Quit()
	}, win)
	q.SetDismissText("I Kown")
	q.SetConfirmText("Quit")
	q.Show()
}

func ShowPasswordDialog(passChan chan string, win fyne.Window) {
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
			// log.Debug("Passwd: confirm ", passwd)
			passChan <- passwd
		} else {
			passChan <- ""
		}
	}, win)

	d.Resize(fyne.NewSize(300, 180))
	d.Show()
}

func RunStrongBoxApp() {
	a := app.New()

	win := a.NewWindow("StrongBox")

	if desk, ok := a.(desktop.App); ok {
		m := fyne.NewMenu("StrongBoxTray",
			fyne.NewMenuItem("Show", func() {
				win.Show()
			}))
		desk.SetSystemTrayMenu(m)
	}

	mountPointInput := widget.NewEntry()
	mountPointInput.SetPlaceHolder("Enter MountPoint...")
	// mountPointInput.Resize(fyne.NewSize(500, 50))

	mountPointSelect := widget.NewButton("...", func() {
		log.Println("Content was")
		dlg := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
			if err == nil && dir != nil {
				log.Println("select:", dir.Path())
			}
		}, win)
		dlg.Show()
	})

	mountRow := container.New(layout.NewGridLayout(2), mountPointInput, mountPointSelect)

	backupInput := widget.NewEntry()
	backupInput.SetPlaceHolder("Enter Backup Path...")
	// mountPointInput.Resize(fyne.NewSize(500, 50))

	backupSelect := widget.NewButton("...", func() {
		log.Println("Content was")
		dlg := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
			if err == nil && dir != nil {
				log.Println("select:", dir.Path())
			}
		}, win)
		dlg.Show()
	})

	backupRow := container.New(layout.NewGridLayout(2), backupInput, backupSelect)

	whitelist := widget.NewButton("Show Process Whitelist", func() {
		log.Println("tapped")
	})

	forbidlist := widget.NewButton("Show Forbid Process", func() {
		log.Println("tapped")
	})

	form := &widget.Form{
		Items: []*widget.FormItem{ // we can specify items in the constructor
			{Text: "Mount Point", Widget: mountRow},
			{Text: "Backup", Widget: backupRow},
			{Text: "Whitelist", Widget: whitelist},
			{Text: "Forbidlist", Widget: forbidlist},
		},
		OnSubmit: func() { // optional, handle form submission
			log.Println("Form submitted")
			log.Println("multiline")
		},
		/*
			OnCancel: func() { // optional, handle form submission
				log.Println("Form submitted")
				log.Println("multiline")
			},
		*/
	}
	form.CancelText = "Save Config"
	form.SubmitText = "Mount"

	// form.Append("Mount Point", mountRow)
	// form.Append("Whitelist", whitelist)

	content := container.NewVBox(
		form,
	)

	win.SetContent(content)
	win.SetCloseIntercept(func() {
		win.Hide()
	})
	win.Resize(fyne.NewSize(650, 480))

	passChan := make(chan string)
	ShowPasswordDialog(passChan, win)

	go func() {
		select {
		case passwd := <-passChan:
			// log.Println("recv pass ", passwd)
			if len(passwd) == 0 {
				ShowQuicDialog(a, "must input passwd", win)
			}
		}
	}()

	win.ShowAndRun()
}
