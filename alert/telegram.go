package alert

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type TelegramNotifier struct {
	token  string
	chatID string
}

func (t *TelegramNotifier) Send(msg string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)
	resp, err := http.PostForm(apiURL, url.Values{
		"chat_id": {t.chatID},
		"text":    {msg},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram %d: %s", resp.StatusCode, body)
	}
	return nil
}
