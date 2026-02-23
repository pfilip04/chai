package mailing

import "fmt"

type User struct {
	Username  string
	UserEmail string
}

type Sender struct {
	SenderName string
	Fulldomain string
	Domain     string
}

func (u *User) ToUser() string {
	return fmt.Sprintf("%s <%s>", u.Username, u.UserEmail)

}

func (s *Sender) FromSender() string {
	return fmt.Sprintf("%s <%s>", s.SenderName, s.Fulldomain)
}
