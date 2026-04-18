package alert

import (
	"fmt"
	"net/smtp"
)

type EmailNotifier struct {
	smtp string // "host:port"
	from string
	to   string
}

func (e *EmailNotifier) Send(subject, body string) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		e.from, e.to, subject, body)
	// Use unauthenticated relay (internal SMTP) or extend with Auth if needed.
	return smtp.SendMail(e.smtp, nil, e.from, []string{e.to}, []byte(msg))
}
