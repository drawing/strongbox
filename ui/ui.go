package ui

import (
	"errors"
	"fmt"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
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
			return errors.New(fmt.Sprintf("must input least %d char", leastPasswdLen))
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

	win.SetContent(widget.NewLabel("Fyne System Tray"))
	win.SetCloseIntercept(func() {
		win.Hide()
	})
	win.Resize(fyne.NewSize(650, 480))

	passChan := make(chan string)
	ShowPasswordDialog(passChan, win)

	go func() {
		select {
		case passwd := <-passChan:
			log.Println("recv pass ", passwd)
			if len(passwd) == 0 {
				ShowQuicDialog(a, "must input passwd", win)
			}
		}
	}()

	win.ShowAndRun()
}
