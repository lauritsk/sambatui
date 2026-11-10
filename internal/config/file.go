package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lauritsk/sambatui/internal/auth"
	"github.com/lauritsk/sambatui/internal/configfile"
	"github.com/lauritsk/sambatui/internal/privatefile"
)

func loadFile(path string, settings *Settings) error {
	data, err := configfile.Read(path, configBytesMax)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return errors.New("invalid configuration: expected a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(settings); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid configuration: expected exactly one JSON object")
	}
	return nil
}

func Save(path string, settings Settings) error {
	if err := settings.Validate(false); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > configBytesMax {
		return errors.New("configuration exceeds 1 MiB")
	}
	return PrivateWrite(path, append(data, '\n'))
}

func SavePassword(path string, password auth.Secret) error {
	if strings.ContainsAny(password.Reveal(), "\r\n") {
		return errors.New("password files support one line only")
	}
	// Include the persisted newline in the same bound enforced by ReadPassword.
	if len(password.Reveal())+1 > passwordLineBytesMax {
		return errors.New("password first line exceeds 1 MiB")
	}
	return PrivateWrite(path, []byte(password.Reveal()+"\n"))
}

func ReadPassword(path string) (string, error) {
	file, err := privatefile.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	// Only the first line, without its line ending. All other whitespace is data.
	line, err := bufio.NewReader(io.LimitReader(file, passwordLineBytesMax+1)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(line) > passwordLineBytesMax {
		return "", errors.New("password first line exceeds 1 MiB")
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func PrivateWrite(path string, data []byte) (result error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(parent, ".sambatui-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer func() {
		if err := os.Remove(temp); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove private temporary file: %w", err))
		}
	}()
	if err = file.Chmod(0o600); err == nil {
		var count int
		count, err = file.Write(data)
		if err == nil && count != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
