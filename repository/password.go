package repository

import (
	"context"
	"os"

	"github.com/danilomarques1/secretumserver/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PasswordRepositoryMongo struct {
	client     *mongo.Client
	collection *mongo.Collection
}

func NewPasswordRepositoryMongo(client *mongo.Client) *PasswordRepositoryMongo {
	collection := client.Database(os.Getenv("DATABASE")).Collection("master")
	collection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.M{"key": 1},
			Options: options.Index().SetUnique(true),
		},
	)

	return &PasswordRepositoryMongo{
		client:     client,
		collection: collection,
	}
}

func (r *PasswordRepositoryMongo) Save(masterId string, password *model.Password) error {
	_, err := r.collection.UpdateOne(context.Background(), bson.M{"_id": masterId}, bson.M{"$addToSet": bson.M{"passwords": password}}, options.Update())
	if err != nil {
		return err
	}
	return nil
}

func (r *PasswordRepositoryMongo) FindByKey(masterId, key string) (*model.Password, error) {
	result := r.collection.FindOne(
		context.Background(),
		bson.M{"_id": masterId, "passwords.key": key}, options.FindOne(),
	)
	master := &model.Master{}
	if err := result.Decode(master); err != nil {
		return nil, err
	}
	password := &master.Passwords[0]

	return password, nil
}
