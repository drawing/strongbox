package securefs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/shirou/gopsutil/v3/process"

	"strongbox/configuration"
	cfg "strongbox/configuration"

	"github.com/hanwen/go-fuse/v2/fuse"
	log "github.com/sirupsen/logrus"
)

// /Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse
var builtInProcess []string = []string{"mount_macfuse", "strongbox"}

const maxProcessCacheSize = 65535

type processItem struct {
	exec   string
	uptime time.Time
}

var processCache *lru.Cache[uint32, *processItem] = nil

/*
func execCmd(pid uint32) {

		timeout := 5
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+5)*time.Second)
		defer cancel()

		cmdarray := []string{"-c", fmt.Sprintf("ps -e -o pid,comm | grep %d", pid)}
		cmd := exec.CommandContext(ctx, "bash", cmdarray...)
		out, err := cmd.CombinedOutput()

		if err != nil {
			log.Error("out err", err)
			return
		}
		log.Printf("out:%s", string(out))
	}
*/

func CheckAllowProcess(action string, ctx context.Context) bool {
	var err error

	caller, ok := fuse.FromContext(ctx)
	if !ok {
		log.Error(action, " FromContext error")
		return false
	}
	log.Debug("Enter PID:", caller.Pid)

	// 2023-08-04 23:46:53 [WARN] Getattr ----- new process start ----- 3102
	if os.Getpid() == int(caller.Pid) || 0 == caller.Pid {
		log.Debug("Leave 1 PID:", caller.Pid)
		return true
	}

	if processCache == nil {
		processCache, err = lru.New[uint32, *processItem](maxProcessCacheSize)
		if err != nil {
			log.Error(action, " lru.New error:", err)
			return false
		}
	}
	ps, ok := processCache.Get(caller.Pid)
	if !ok || ps.uptime.After(time.Now().Add(30*time.Second)) {
		log.Warn(action, " ----- new process start ----- ", caller.Pid)
		nps, err := process.NewProcess(int32(caller.Pid))
		if err != nil {
			log.Error(action, " process.NewProcess error:", err)
			return false
		}
		exeFile, err := nps.Exe()
		if err != nil {
			log.Error(action, " ps.Exe error:", err)
			return false
		}

		log.Warn(action, " ----- new process end ----- ", caller.Pid, ", ", exeFile)
		ps = &processItem{exeFile, time.Now()}
		processCache.Add(caller.Pid, ps)
	}

	for _, v := range configuration.Cfg.AllowProcess {
		if ps.exec == v {
			log.Debug("Leave 2 PID:", caller.Pid)
			return true
		}
	}

	if cfg.Cfg.WatchMode {
		log.Warn(action, " process forbid(WatchMode):", caller.Pid, " ", ps.exec, ", ", os.Getpid())
		return true
	}
	log.Debug("Leave 3 PID:", caller.Pid)
	log.Warn(action, " process forbid:", caller.Pid, " ", ps.exec, ", ", os.Getpid())
	return false
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])

	if unpadding > len(origData) {
		log.Error("unpadding too large:", unpadding)
		return origData
	}

	return origData[:(length - unpadding)]
}

func AESEncrypt(plaintext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	plaintext = PKCS7Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(plaintext))

	blockMode.CryptBlocks(crypted, plaintext)

	return crypted, nil
}

func AESDecrypt(ciphertext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, os.ErrInvalid
	}

	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(origData, ciphertext)

	origData = PKCS7UnPadding(origData)

	return origData, nil
}

func intToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func bytesToInt(b []byte) int {
	var x int32
	bytesBuffer := bytes.NewBuffer(b)
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}
