package tui

import "strconv"

func formatSetting(value int32) string {
	return strconv.FormatInt(int64(value), 10)
}

func parseSetting(text string) (int32, error) {
	value, err := strconv.ParseInt(text, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(value), nil
}
