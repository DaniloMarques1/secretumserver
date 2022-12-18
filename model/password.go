package model

type Password struct {
	Id  string `bson:"_id"`
	Key string `bson:"key"`
}

type PasswordRepository interface {
	Save(*Password) error
}
