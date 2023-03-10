package model

type Password struct {
	Id  string `bson:"_id"`
	Key string `bson:"key"`
	Pwd string `bson:"password"`
}

type PasswordRepository interface {
	Save(string, *Password) error
	FindByKey(string, string) (*Password, error)
	Remove(string, *Password) error
	FindKeys(string) ([]string, error)
	Update(string, *Password) error
}
