package repository

import (
	"context"
	"log"
	"os"

	"github.com/danilomarques1/secretumserver/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MasterRepositoryMongo struct {
	client     *mongo.Client
	collection *mongo.Collection
}

func NewMasterRepository(client *mongo.Client) *MasterRepositoryMongo {
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
	}
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
