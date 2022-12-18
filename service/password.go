package service

import (
	"context"
	"errors"

	"github.com/danilomarques1/secretumserver/model"
	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/token"
	"github.com/google/uuid"
)

var (
	ErrKeyAlreadyUsed = errors.New("Key already used")
)

type PasswordService struct {
	pb.UnimplementedPasswordServer
	repository model.PasswordRepository
}

func NewPasswordService(repository model.PasswordRepository) *PasswordService {
	return &PasswordService{
		repository: repository,
	}
}

func (ps *PasswordService) SavePassword(context context.Context, in *pb.CreatePasswordRequest) (*pb.CreatePasswordResponse, error) {
	if err := validateCreatePasswordRequest(in); err != nil {
		return nil, err
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}
	masterId := claims.MasterId

	if _, err := ps.repository.FindByKey(masterId, in.GetKey()); err == nil {
		return nil, ErrKeyAlreadyUsed
	}

	password := &model.Password{
		Id:  uuid.NewString(),
		Key: in.GetKey(),
		Pwd: in.GetPassword(),
	}

	if err := ps.repository.Save(masterId, password); err != nil {
		return nil, err
	}

	return &pb.CreatePasswordResponse{OK: true}, nil
}

func (ps *PasswordService) FindPassword(ctx context.Context, in *pb.FindPasswordRequest) (*pb.FindPasswordResponse, error) {
	if err := validateFindPasswordRequest(in); err != nil {
		return nil, err
	}
	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}

	masterId := claims.MasterId
	password, err := ps.repository.FindByKey(masterId, in.GetKey())
	if err != nil {
		return nil, err
	}
	return &pb.FindPasswordResponse{
		Id:       password.Id,
		Key:      password.Key,
		Password: password.Pwd,
	}, nil
}

func validateCreatePasswordRequest(request *pb.CreatePasswordRequest) error {
	if len(request.GetKey()) == 0 || len(request.GetPassword()) == 0 || len(request.GetAccessToken()) == 0 {
		return ErrValidation
	}
	return nil
}

func validateFindPasswordRequest(request *pb.FindPasswordRequest) error {
	if len(request.GetAccessToken()) == 0 || len(request.GetKey()) == 0 {
		return ErrValidation
	}
	return nil
}
