package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/repository"
	"github.com/danilomarques1/secretumserver/service"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	client, err := mongo.Connect(
		context.Background(),
		options.Client().ApplyURI(os.Getenv("DATABASE_URI")),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Ping(context.Background(), nil); err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", os.Getenv("PORT")))
	if err != nil {
		log.Fatal(err)
	}

	masterRepo := repository.NewMasterRepository(client)
	passwordRepo := repository.NewPasswordRepositoryMongo(client)

	masterService := service.NewMasterService(masterRepo)
	passwordService := service.NewPasswordService(passwordRepo)

	server := grpc.NewServer()
	pb.RegisterMasterServer(server, masterService)
	pb.RegisterPasswordServer(server, passwordService)

	log.Printf("Starting grpc server")
	if err := server.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
