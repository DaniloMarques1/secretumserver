package repository

import (
	"context"
	"os"

	"github.com/danilomarques1/secretumserver/model"
	"go.mongodb.org/mongo-driver/mongo"
)

type MasterRepositoryMongo struct {
    client *mongo.Client
    collection *mongo.Collection
}

func NewMasterRepository(client *mongo.Client) *MasterRepositoryMongo {
    collection := client.Database(os.Getenv("DATABASE")).Collection("master")
    return &MasterRepositoryMongo{
        client: client,
        collection: collection,
    }
}

func (r *MasterRepositoryMongo) Save(master *model.Master) error {
    if _, err := r.collection.InsertOne(context.Background(), master); err != nil {
        return err
    }

    return nil
}
