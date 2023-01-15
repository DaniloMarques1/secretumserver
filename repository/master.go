package repository

import (
	"context"
	"log"
	"os"

	"github.com/danilomarques1/secretumserver/database"
	"github.com/danilomarques1/secretumserver/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MasterRepositoryMongo struct {
	client     *mongo.Client
	collection *mongo.Collection
}

func NewMasterRepository() (*MasterRepositoryMongo, error) {
	client, err := database.GetDatabaseConnection()
	if err != nil {
		return nil, err
	}
	collection := client.Database(os.Getenv("DATABASE")).Collection("master")
	collection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.M{"email": 1},
			Options: options.Index().SetUnique(true),
		},
	)

	return &MasterRepositoryMongo{
		client:     client,
		collection: collection,
	}, nil
}

func (r *MasterRepositoryMongo) Save(master *model.Master) error {
	if _, err := r.collection.InsertOne(context.Background(), master); err != nil {
		log.Printf("Error when trying to insert %v\n", err)
		return err
	}

	return nil
}

func (r *MasterRepositoryMongo) FindByEmail(email string) (*model.Master, error) {
	master := &model.Master{}
	result := r.collection.FindOne(context.Background(), bson.M{"email": email}, options.FindOne())
	if err := result.Decode(master); err != nil {
		return nil, err
	}

	return master, nil
}

func (r *MasterRepositoryMongo) Update(master *model.Master) error {
	filter := bson.M{"email": master.Email}
	update := bson.M{"$set": master}
	if _, err := r.collection.UpdateOne(context.Background(), filter, update, options.Update()); err != nil {
		return err
	}
	return nil
}
