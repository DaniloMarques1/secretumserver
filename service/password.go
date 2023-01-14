package service

import (
	"context"
	"log"

	"github.com/danilomarques1/secretumserver/generate"
	"github.com/danilomarques1/secretumserver/model"
	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/repository"
	"github.com/danilomarques1/secretumserver/token"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrKeyAlreadyUsed = "Key already used"
)

type PasswordService struct {
	pb.UnimplementedPasswordServer
	passwordRepository model.PasswordRepository
}

func NewPasswordService() (*PasswordService, error) {
	passwordRepository, err := repository.NewPasswordRepository()
	if err != nil {
		return nil, err
	}
	return &PasswordService{
		passwordRepository: passwordRepository,
	}, nil
}

func (ps *PasswordService) SavePassword(context context.Context, in *pb.CreatePasswordRequest) (*pb.CreatePasswordResponse, error) {
	if !isValidCreatePasswordRequest(in) {
		return nil, status.Errorf(
			codes.InvalidArgument,
			ErrValidation,
		)
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}
	masterId := claims.MasterId

	if _, err := ps.passwordRepository.FindByKey(masterId, in.GetKey()); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, ErrKeyAlreadyUsed)
	}

	password := &model.Password{
		Id:  uuid.NewString(),
		Key: in.GetKey(),
		Pwd: in.GetPassword(),
	}

	if err := ps.passwordRepository.Save(masterId, password); err != nil {
		return nil, err
	}

	return &pb.CreatePasswordResponse{OK: true}, nil
}

func (ps *PasswordService) FindPassword(ctx context.Context, in *pb.FindPasswordRequest) (*pb.FindPasswordResponse, error) {
	if !isValidteFindPasswordRequest(in) {
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}

	masterId := claims.MasterId
	password, err := ps.passwordRepository.FindByKey(masterId, in.GetKey())
	if err != nil {
		return nil, err
	}
	return &pb.FindPasswordResponse{
		Id:       password.Id,
		Key:      password.Key,
		Password: password.Pwd,
	}, nil
}

func (ps *PasswordService) RemovePassword(ctx context.Context, in *pb.RemovePasswordRequest) (*pb.RemovePasswordResponse, error) {
	log.Printf("request = %v\n", in)

	if !isValidRemovePasswordRequest(in) {
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}

	password, err := ps.passwordRepository.FindByKey(claims.MasterId, in.GetKey())
	if err != nil {
		return nil, err
	}

	if err := ps.passwordRepository.Remove(claims.MasterId, password); err != nil {
		return nil, err
	}

	return &pb.RemovePasswordResponse{OK: true}, nil
}

func (ps *PasswordService) FindKeys(ctx context.Context, in *pb.FindKeysRequest) (*pb.FindKeysResponse, error) {
	if !isValidFindKeysRequest(in) {
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}

	keys, err := ps.passwordRepository.FindKeys(claims.MasterId)
	if err != nil {
		return nil, err
	}

	return &pb.FindKeysResponse{Keys: keys}, nil
}

func (ps *PasswordService) UpdatePassword(ctx context.Context, in *pb.UpdatePasswordRequest) (*pb.UpdatePasswordResponse, error) {
	log.Printf("Update request = %#v\n", in)
	if !isValidUpdatePasswordRequest(in) {
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}

	password, err := ps.passwordRepository.FindByKey(claims.MasterId, in.GetKey())
	if err != nil {
		return nil, err
	}

	password.Pwd = in.GetPassword()
	if err := ps.passwordRepository.Update(claims.MasterId, password); err != nil {
		return nil, err
	}

	return &pb.UpdatePasswordResponse{OK: true}, nil
}

func (ps *PasswordService) GeneratePassword(ctx context.Context, in *pb.GeneratePasswordRequest) (*pb.GeneratePasswordResponse, error) {
	if !isValidGeneratePasswordRequest(in) {
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}

	if _, err := ps.passwordRepository.FindByKey(claims.MasterId, in.GetKey()); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, ErrKeyAlreadyUsed)
	}

	generatedPassword := generate.GeneratePassword(in.GetKeyphrase())
	password := &model.Password{
		Id:  uuid.NewString(),
		Key: in.GetKey(),
		Pwd: generatedPassword,
	}

	if err := ps.passwordRepository.Save(claims.MasterId, password); err != nil {
		return nil, err
	}

	return &pb.GeneratePasswordResponse{Id: password.Id, Key: password.Key, Password: password.Pwd}, nil
}

func isValidCreatePasswordRequest(request *pb.CreatePasswordRequest) bool {
	return len(request.GetKey()) > 0 && len(request.GetPassword()) > 0 && len(request.GetAccessToken()) > 0
}

func isValidteFindPasswordRequest(request *pb.FindPasswordRequest) bool {
	return len(request.GetAccessToken()) > 0 && len(request.GetKey()) > 0
}

func isValidRemovePasswordRequest(request *pb.RemovePasswordRequest) bool {
	return len(request.GetAccessToken()) > 0 && len(request.GetKey()) > 0
}

func isValidFindKeysRequest(request *pb.FindKeysRequest) bool {
	return len(request.GetAccessToken()) > 0
}

func isValidUpdatePasswordRequest(request *pb.UpdatePasswordRequest) bool {
	return len(request.GetKey()) > 0 && len(request.GetPassword()) > 0 && len(request.GetAccessToken()) == 0
}

func isValidGeneratePasswordRequest(request *pb.GeneratePasswordRequest) bool {
	return len(request.GetAccessToken()) > 0 && len(request.GetKey()) == 0 && len(request.GetKeyphrase()) > 0
}
