package service

import (
	"context"
	"errors"
	"time"

	"github.com/danilomarques1/secretumserver/model"
	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/repository"
	"github.com/danilomarques1/secretumserver/token"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrValidation       = errors.New("Error validating request body")
	ErrEmailAlreadyUsed = errors.New("Master email already used")
	ErrPasswordExpired  = errors.New("Password has expired")
)

type MasterService struct {
	pb.UnimplementedMasterServer
	masterRepo model.MasterRepository
}

func NewMasterService() (*MasterService, error) {
	masterRepo, err := repository.NewMasterRepository()
	if err != nil {
		return nil, err
	}

	return &MasterService{
		masterRepo: masterRepo,
	}, nil
}

func (ms *MasterService) SaveMaster(ctx context.Context, in *pb.CreateMasterRequest) (*pb.CreateMasterResponse, error) {
	if err := validateCreateMasterRequest(in); err != nil {
		return nil, err
	}

	if _, err := ms.masterRepo.FindByEmail(in.GetEmail()); err == nil {
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
		Passwords:         []model.Password{},
	}

	if err := ms.masterRepo.Save(master); err != nil {
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

	master, err := ms.masterRepo.FindByEmail(in.GetEmail())
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(master.Pwd), []byte(in.GetPassword())); err != nil {
		return nil, err
	}

	// TODO: need to think a way so the client knows that it
	// needs to require a password update
	if master.PwdExpirationDate.Unix() <= time.Now().Unix() {
		return nil, ErrPasswordExpired
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
