package securefs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"

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

var processCache *lru.Cache[uint32, *process.Process] = nil
 
func CheckAllowProcess(action string, ctx context.Context) bool {
	var err error

	caller, ok := fuse.FromContext(ctx)
	if !ok {
		log.Error(action, " FromContext error")
		return false
	}
	if os.Getpid() == int(caller.Pid) || 0 == caller.Pid {
		return true
	}

	if processCache == nil {
		processCache, err = lru.New[uint32, *process.Process](maxProcessCacheSize)
		if err != nil {
			log.Error(action, " lru.New error:", err)
			return false
		}
	}
	ps, ok := processCache.Get(caller.Pid)
	if ok {
		running, err := ps.IsRunning()
		if !running || err != nil {
			processCache.Remove(caller.Pid)
			ok = false
		}
	}
	if !ok {
		ps, err = process.NewProcess(int32(caller.Pid))
		if err != nil {
			log.Error(action, " process.NewProcess error:", err)
			return false
		}
		processCache.Add(caller.Pid, ps)
	}

	exeFile, err := ps.Exe()
	if err != nil {
		processCache.Remove(caller.Pid)
		return false
	}

	for _, v := range configuration.Cfg.AllowProcess {
		if exeFile == v {
			return true
		}
	}

	if cfg.Cfg.WatchMode {
		log.Warn(action, " process forbid(WatchMode):", caller.Pid, " ", exeFile, ", ", os.Getpid())
		return true
	}
	log.Warn(action, " process forbid:", caller.Pid, " ", exeFile, ", ", os.Getpid())
	return false
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	// log.Debug("padding:", padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	if unpadding > len(origData) {
		log.Error("unpadding too large:", unpadding)
		return origData
	}

	// log.Debug("unpadding:", unpadding)
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
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int(x)
}
