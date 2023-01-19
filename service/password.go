package service

import (
	"context"
	"log"

	"github.com/danilomarques1/secretumserver/encrypt"
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
	e                  encrypt.Encrypt
	d                  encrypt.Decrypt
}

func NewPasswordService() (*PasswordService, error) {
	passwordRepository, err := repository.NewPasswordRepository()
	if err != nil {
		log.Printf("Error creating password service %v\n", err)
		return nil, err
	}
	e, err := encrypt.NewEncrypt()
	if err != nil {
		log.Printf("error getting encryption type %v\n", err)
		return nil, err
	}
	d, err := encrypt.NewDecrypt()
	if err != nil {
		log.Printf("error getting decryption type %v\n", err)
		return nil, err
	}

	return &PasswordService{
		passwordRepository: passwordRepository,
		e:                  e,
		d:                  d,
	}, nil
}

func (ps *PasswordService) SavePassword(context context.Context, in *pb.CreatePasswordRequest) (*pb.CreatePasswordResponse, error) {
	if !isValidCreatePasswordRequest(in) {
		log.Printf("Error validating save password request\n")
		return nil, status.Errorf(
			codes.InvalidArgument,
			ErrValidation,
		)
	}

	claims, err := token.ValidateAccessToken(in.GetAccessToken())
	if err != nil {
		log.Printf("Error validating token %v\n", err)
		return nil, err
	}
	masterId := claims.MasterId

	if _, err := ps.passwordRepository.FindByKey(masterId, in.GetKey()); err == nil {
		log.Printf("Error because is already registered\n")
		return nil, status.Errorf(codes.AlreadyExists, ErrKeyAlreadyUsed)
	}

	encrypted, err := ps.e.EncryptMessage(in.GetPassword())
	if err != nil {
		log.Printf("Error while encrypting password %v\n", err)
		return nil, err
	}

	password := &model.Password{
		Id:  uuid.NewString(),
		Key: in.GetKey(),
		Pwd: encrypted,
	}

	if err := ps.passwordRepository.Save(masterId, password); err != nil {
		log.Printf("Error while saving password %v\n", err)
		return nil, err
	}

	return &pb.CreatePasswordResponse{OK: true}, nil
}

func (ps *PasswordService) FindPassword(ctx context.Context, in *pb.FindPasswordRequest) (*pb.FindPasswordResponse, error) {
	if !isValidteFindPasswordRequest(in) {
		log.Printf("Error validating find password request\n")
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateAccessToken(in.GetAccessToken())
	if err != nil {
		log.Printf("Error validating token %v\n", err)
		return nil, err
	}

	masterId := claims.MasterId
	password, err := ps.passwordRepository.FindByKey(masterId, in.GetKey())
	if err != nil {
		log.Printf("Error finding the password %v\n", err)
		return nil, err
	}

	decrypted, err := ps.d.DecryptMessage(password.Pwd)
	if err != nil {
		log.Printf("Error while decrypting password %v\n", err)
		return nil, err
	}

	return &pb.FindPasswordResponse{
		Id:       password.Id,
		Key:      password.Key,
		Password: decrypted,
	}, nil
}

func (ps *PasswordService) RemovePassword(ctx context.Context, in *pb.RemovePasswordRequest) (*pb.RemovePasswordResponse, error) {
	if !isValidRemovePasswordRequest(in) {
		log.Printf("Error validating remove password request\n")
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateAccessToken(in.GetAccessToken())
	if err != nil {
		log.Printf("Error validating token %v\n", err)
		return nil, err
	}

	password, err := ps.passwordRepository.FindByKey(claims.MasterId, in.GetKey())
	if err != nil {
		log.Printf("Error finding password by key %v\n", err)
		return nil, err
	}

	if err := ps.passwordRepository.Remove(claims.MasterId, password); err != nil {
		log.Printf("Error removing password %v\n", err)
		return nil, err
	}

	return &pb.RemovePasswordResponse{OK: true}, nil
}

func (ps *PasswordService) FindKeys(ctx context.Context, in *pb.FindKeysRequest) (*pb.FindKeysResponse, error) {
	if !isValidFindKeysRequest(in) {
		log.Printf("Error validating find keys request\n")
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateAccessToken(in.GetAccessToken())
	if err != nil {
		log.Printf("Error validating token %v\n", err)
		return nil, err
	}

	keys, err := ps.passwordRepository.FindKeys(claims.MasterId)
	if err != nil {
		return nil, err
	}

	return &pb.FindKeysResponse{Keys: keys}, nil
}

func (ps *PasswordService) UpdatePassword(ctx context.Context, in *pb.UpdatePasswordRequest) (*pb.UpdatePasswordResponse, error) {
	if !isValidUpdatePasswordRequest(in) {
		log.Printf("Error validating update password request\n")
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateAccessToken(in.GetAccessToken())
	if err != nil {
		log.Printf("Error validating token %v\n", err)
		return nil, err
	}

	password, err := ps.passwordRepository.FindByKey(claims.MasterId, in.GetKey())
	if err != nil {
		log.Printf("Error finding the password %v\n", err)
		return nil, err
	}

	encrypted, err := ps.e.EncryptMessage(in.GetPassword())
	if err != nil {
		log.Printf("Error encrypting password %v\n", err)
		return nil, err
	}

	password.Pwd = encrypted
	if err := ps.passwordRepository.Update(claims.MasterId, password); err != nil {
		log.Printf("Error updating password %v\n", err)
		return nil, err
	}

	return &pb.UpdatePasswordResponse{OK: true}, nil
}

func (ps *PasswordService) GeneratePassword(ctx context.Context, in *pb.GeneratePasswordRequest) (*pb.GeneratePasswordResponse, error) {
	if !isValidGeneratePasswordRequest(in) {
		log.Printf("Error validating find password request\n")
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateAccessToken(in.GetAccessToken())
	if err != nil {
		log.Printf("Error validating token %v\n", err)
		return nil, err
	}

	if _, err := ps.passwordRepository.FindByKey(claims.MasterId, in.GetKey()); err == nil {
		log.Printf("Error because is already registered\n")
		return nil, status.Errorf(codes.AlreadyExists, ErrKeyAlreadyUsed)
	}

	generatedPassword := generate.GeneratePassword(in.GetKeyphrase())
	encrypted, err := ps.e.EncryptMessage(generatedPassword)
	if err != nil {
		log.Printf("Error encrypting message %v\n", err)
		return nil, err
	}
	password := &model.Password{
		Id:  uuid.NewString(),
		Key: in.GetKey(),
		Pwd: encrypted,
	}

	if err := ps.passwordRepository.Save(claims.MasterId, password); err != nil {
		log.Printf("error when saving password %v\n", err)
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
	return len(request.GetAccessToken()) > 0 && len(request.GetKey()) > 0 && len(request.GetKeyphrase()) > 0
}
