package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

//TIP To run your code, right-click the code and select <b>Run</b>. Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.

func main() {
	fmt.Println("Welcome to the EncryptionDecryption Tool !!")
	fmt.Println("Enter 1 to encrypt a file")
	fmt.Println("Enter 2 to decrypt a file")
	fmt.Printf("Enter Your Choice: ")
	var choice int
	_, err := fmt.Scan(&choice)
	if err != nil {
		fmt.Println("Enter a valid choice")
		return
	}
	fmt.Printf("Enter File Name: ")
	var fileName string
	_, err = fmt.Scan(&fileName)
	if err != nil {
		fmt.Println("Enter a valid file")
		return
	}
	data, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Println("File reading error", err)
		return
	}
	var key string
	fmt.Printf("Enter your key: ")
	_, err = fmt.Scan(&key)
	if err != nil {
		fmt.Println("Enter a valid key")
		return
	}
	key = makeValidKey(key)
	if choice == 1 {
		encryptedMessage, err := encrypt(key, string(data))
		if err != nil {
			fmt.Println("Encrypt error", err)
			return
		}
		err = os.WriteFile(fileName, []byte(encryptedMessage), 0644)
		if err != nil {
			fmt.Println("File writing error", err)
			return
		}
		fmt.Println("File Encrypted Successfully")
	} else if choice == 2 {
		decryptedMessage, err := decrypt(key, string(data))
		if err != nil {
			fmt.Println("Decrypt error", err)
			return
		}
		err = os.WriteFile(fileName, []byte(decryptedMessage), 0644)
		if err != nil {
			fmt.Println("File writing error", err)
			return
		}
		fmt.Println("File Decrypted Successfully")
	} else {
		fmt.Println("Invalid choice")
	}
}
func encrypt(key string, message string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	var paddedMessage []byte
	paddedMessage = PadPKCS7([]byte(message), block.BlockSize())
	msgBytes := make([]byte, len(paddedMessage))
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(msgBytes, paddedMessage)
	return hex.EncodeToString(append(iv, msgBytes...)), nil
}
func decrypt(key string, encryptedMessage string) (string, error) {
	txt, err := hex.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}
	if len(txt) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := txt[:aes.BlockSize]
	txt = txt[aes.BlockSize:]
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	paddedData := make([]byte, len(txt))
	cbc.CryptBlocks(paddedData, txt)
	unpaddedData, err := UnpadPKCS7(paddedData)
	if err != nil {
		return "", err
	}
	return string(unpaddedData), nil
}
func makeValidKey(key string) string {
	if len(key) < 16 {
		for len(key) < 16 {
			key += key
		}
	}
	key = key[:16]
	return key
}

func PadPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	paddingtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, paddingtext...)
}
func UnpadPKCS7(data []byte) ([]byte, error) {
	padding := data[len(data)-1]
	if int(padding) > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-int(padding)], nil
}

//TIP See GoLand help at <a href="https://www.jetbrains.com/help/go/">jetbrains.com/help/go/</a>.
// Also, you can try interactive lessons for GoLand by selecting 'Help | Learn IDE Features' from the main menu.
