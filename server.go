package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/service"
	"google.golang.org/grpc"
)

type Server struct {
	gServer *grpc.Server
}

func NewServer() (*Server, error) {
	masterService, err := service.NewMasterService()
	if err != nil {
		return nil, err
	}
	passwordService, err := service.NewPasswordService()
	if err != nil {
		return nil, err
	}
	gServer := grpc.NewServer()
	pb.RegisterMasterServer(gServer, masterService)
	pb.RegisterPasswordServer(gServer, passwordService)
	s := &Server{
		gServer: gServer,
	}

	return s, nil
}

func (s *Server) Run() error {
	port := os.Getenv("PORT")
	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		return err
	}
	defer lis.Close()

	log.Printf("Starting grpc server on port %v\n", port)
	if err := s.gServer.Serve(lis); err != nil {
		return err
	}

	return nil
}
