package service

import (
	"context"
	"errors"
	"time"

	"github.com/danilomarques1/secretumserver/model"
	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/token"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrValidation       = errors.New("Error validating request body")
	ErrEmailAlreadyUsed = errors.New("Master email already used")
)

type MasterService struct {
	pb.UnimplementedMasterServer
	repository model.MasterRepository
}

func NewMasterService(repository model.MasterRepository) *MasterService {
	return &MasterService{
		repository: repository,
	}
}

func (ms *MasterService) SaveMaster(ctx context.Context, in *pb.CreateMasterRequest) (*pb.CreateMasterResponse, error) {
	if err := validateCreateMasterRequest(in); err != nil {
		return nil, err
	}

	if _, err := ms.repository.FindByEmail(in.GetEmail()); err == nil {
		return nil, ErrEmailAlreadyUsed
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(in.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	masterPwdExpiration := time.Now().AddDate(0, 0, 30)

	master := &model.Master{
		Id:                uuid.NewString(),
		Email:             in.GetEmail(),
		Pwd:               string(hashedPwd),
		PwdExpirationDate: masterPwdExpiration,
	}

	if err := ms.repository.Save(master); err != nil {
		return nil, err
	}

	return &pb.CreateMasterResponse{
		OK: true,
	}, nil
}

func (ms *MasterService) AuthenticateMaster(ctx context.Context, in *pb.AuthMasterRequest) (*pb.AuthMasterResponse, error) {
	if err := validateAuthMasterRequest(in); err != nil {
		return nil, err
	}

	master, err := ms.repository.FindByEmail(in.GetEmail())
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(master.Pwd), []byte(in.GetPassword())); err != nil {
		return nil, err
	}

	tokenStr, err := token.GetToken(master.Id)
	if err != nil {
		return nil, err
	}

	return &pb.AuthMasterResponse{
		AccessToken: tokenStr,
		ExpiresIn:   token.ExpiresIn,
	}, nil
}

func validateCreateMasterRequest(request *pb.CreateMasterRequest) error {
	if len(request.GetEmail()) > 0 && len(request.GetPassword()) > 0 {
		return nil
	}

	return ErrValidation
}

func validateAuthMasterRequest(request *pb.AuthMasterRequest) error {
	if len(request.GetEmail()) > 0 && len(request.GetPassword()) > 0 {
		return nil
	}

	return ErrValidation
}
