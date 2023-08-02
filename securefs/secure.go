package securefs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"

	ps "github.com/mitchellh/go-ps"
	log "github.com/sirupsen/logrus"

	"strongbox/configuration"

	"github.com/hanwen/go-fuse/v2/fuse"
)

var builtInProcess []string = []string{"mount_macfuse", "strongbox"}

func CheckAllowProcess(action string, ctx context.Context) bool {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		log.Error(action, " FromContext error")
		return false
	}
	if os.Getpid() == int(caller.Pid) || 0 == caller.Pid {
		return true
	}

	process, err := ps.FindProcess(int(caller.Pid))
	if err != nil {
		log.Debug(action, " process error:", caller.Pid, " ", err)
		return false
	} else {
		// log.Debug(action, " process:", caller.Pid, " ", process.Executable())
	}

	for _, v := range builtInProcess {
		if process.Executable() == v {
			return true
		}
	}
	for _, v := range configuration.Cfg.AllowProcess {
		if process.Executable() == v {
			return true
		}
	}

	log.Warn(action, " process forbid:", caller.Pid, " ", process.Executable())
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
