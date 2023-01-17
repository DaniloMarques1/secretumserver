package repository

import (
	"context"
	"errors"
	"os"

	"github.com/danilomarques1/secretumserver/database"
	"github.com/danilomarques1/secretumserver/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PasswordRepositoryMongo struct {
	client     *mongo.Client
	collection *mongo.Collection
}

func NewPasswordRepository() (*PasswordRepositoryMongo, error) {
	client, err := database.GetDatabaseConnection()
	if err != nil {
		return nil, err
	}
	collection := client.Database(os.Getenv("DATABASE")).Collection("master")
	collection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys: bson.M{"passwords.key": 1},
		},
	)

	return &PasswordRepositoryMongo{
		client:     client,
		collection: collection,
	}, nil
}

func (r *PasswordRepositoryMongo) Save(masterId string, password *model.Password) error {
	_, err := r.collection.UpdateOne(
		context.Background(),
		bson.M{"_id": masterId},
		bson.M{"$addToSet": bson.M{"passwords": password}},
		options.Update(),
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *PasswordRepositoryMongo) FindByKey(masterId, key string) (*model.Password, error) {
	result := r.collection.FindOne(
		context.Background(),
		bson.M{"_id": masterId, "passwords.key": key},
		options.FindOne().SetProjection(bson.M{"passwords": bson.M{"$elemMatch": bson.M{"key": key}}}),
	)
	master := &model.Master{}
	if err := result.Decode(master); err != nil {
		return nil, err
	}
	if len(master.Passwords) == 0 {
		return nil, errors.New("No password found")
	}

	password := &master.Passwords[0]
	return password, nil
}

func (r *PasswordRepositoryMongo) Remove(masterId string, password *model.Password) error {
	_, err := r.collection.UpdateOne(
		context.Background(),
		bson.M{"_id": masterId},
		bson.M{"$pull": bson.M{"passwords": bson.M{"key": password.Key}}}, options.Update(),
	)

	if err != nil {
		return err
	}

	return nil
}

func (r *PasswordRepositoryMongo) FindKeys(masterId string) ([]string, error) {
	result := r.collection.FindOne(context.Background(), bson.M{"_id": masterId}, options.FindOne())
	master := &model.Master{}
	if err := result.Decode(master); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(master.Passwords))
	for _, password := range master.Passwords {
		keys = append(keys, password.Key)
	}

	return keys, nil
}

func (r *PasswordRepositoryMongo) Update(masterId string, password *model.Password) error {
	filter := bson.M{"_id": masterId, "passwords.key": password.Key}
	update := bson.M{"$set": bson.M{"passwords.$.password": password.Pwd}}
	if _, err := r.collection.UpdateOne(context.Background(), filter, update, options.Update()); err != nil {
		return err
	}

	return nil
}
