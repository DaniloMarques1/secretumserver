package service

import (
	"context"
	"errors"
	"log"

	"github.com/danilomarques1/secretumserver/generate"
	"github.com/danilomarques1/secretumserver/model"
	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/repository"
	"github.com/danilomarques1/secretumserver/token"
	"github.com/google/uuid"
)

var (
	ErrKeyAlreadyUsed = errors.New("Key already used")
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
	if err := validateCreatePasswordRequest(in); err != nil {
		return nil, err
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}
	masterId := claims.MasterId

	if _, err := ps.passwordRepository.FindByKey(masterId, in.GetKey()); err == nil {
		return nil, ErrKeyAlreadyUsed
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
	if err := validateFindPasswordRequest(in); err != nil {
		return nil, err
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

	if err := validateRemovePasswordRequest(in); err != nil {
		return nil, err
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
	if err := validateFindKeysRequest(in); err != nil {
		return nil, err
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
	if err := validateUpdatePasswordRequest(in); err != nil {
		return nil, err
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
	if err := validateGeneratePasswordRequest(in); err != nil {
		return nil, err
	}

	claims, err := token.ValidateToken(in.GetAccessToken())
	if err != nil {
		return nil, err
	}

	if _, err := ps.passwordRepository.FindByKey(claims.MasterId, in.GetKey()); err == nil {
		return nil, ErrKeyAlreadyUsed
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

func validateRemovePasswordRequest(request *pb.RemovePasswordRequest) error {
	if len(request.GetAccessToken()) == 0 || len(request.GetKey()) == 0 {
		return ErrValidation
	}
	return nil
}

func validateFindKeysRequest(request *pb.FindKeysRequest) error {
	if len(request.GetAccessToken()) == 0 {
		return ErrValidation
	}
	return nil
}

func validateUpdatePasswordRequest(request *pb.UpdatePasswordRequest) error {
	if len(request.GetKey()) == 0 || len(request.GetPassword()) == 0 || len(request.GetAccessToken()) == 0 {
		return ErrValidation
	}
	return nil
}

func validateGeneratePasswordRequest(request *pb.GeneratePasswordRequest) error {
	if len(request.GetAccessToken()) == 0 || len(request.GetKey()) == 0 || len(request.GetKeyphrase()) == 0 {
		return ErrValidation
	}
	return nil
}
