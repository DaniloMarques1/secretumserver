package repository

import (
	"context"
	"log"
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
        log.Printf("Error when trying to insert %v\n", err)
        return err
    }

    return nil
}
