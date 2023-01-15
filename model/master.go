package model

import "time"

type Master struct {
	Id                string     `bson:"_id"`
	Email             string     `bson:"email"`
	Pwd               string     `bson:"password"`
	PwdExpirationDate time.Time  `bson:"password_expiration_date"`
	Passwords         []Password `bson:"passwords"`
}

type MasterRepository interface {
	Save(*Master) error
	FindByEmail(string) (*Master, error)
	Update(*Master) error
}
