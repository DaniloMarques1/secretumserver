package service

import (
	"context"
	"time"

	"github.com/danilomarques1/secretumserver/model"
	"github.com/danilomarques1/secretumserver/pb"
	"github.com/danilomarques1/secretumserver/repository"
	"github.com/danilomarques1/secretumserver/token"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ErrValidation       = "Error validating request body"
	ErrEmailAlreadyUsed = "Master email already used"
	ErrPasswordExpired  = "Password has expired"
	ErrWrongPassword    = "The given password is invalid"
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
	if !isValidCreateMasterRequest(in) {
		return nil, status.Errorf(
			codes.InvalidArgument,
			ErrValidation,
		)
	}

	if _, err := ms.masterRepo.FindByEmail(in.GetEmail()); err == nil {
		return nil, status.Errorf(
			codes.AlreadyExists,
			ErrEmailAlreadyUsed,
		)
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(in.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	masterPwdExpiration := ms.getPasswordExpirationDate()
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
	if !isValidteAuthMasterRequest(in) {
		return nil, status.Errorf(
			codes.InvalidArgument,
			ErrValidation,
		)
	}

	master, err := ms.masterRepo.FindByEmail(in.GetEmail())
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(master.Pwd), []byte(in.GetPassword())); err != nil {
		return nil, status.Errorf(codes.NotFound, ErrWrongPassword)
	}

	// by returning PermissionDenied the client will interpret it
	// as needing to update the password
	if master.PwdExpirationDate.Unix() <= time.Now().Unix() {
		return nil, status.Errorf(
			codes.PermissionDenied,
			ErrPasswordExpired,
		)
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

func (ms *MasterService) UpdateMaster(ctx context.Context, in *pb.UpdateMasterRequest) (*pb.UpdateMasterResponse, error) {
	if !isValidUpdateMasterRequest(in) {
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}
	master, err := ms.masterRepo.FindByEmail(in.GetEmail())
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(master.Pwd), []byte(in.GetOldPassword())); err != nil {
		return nil, status.Errorf(codes.NotFound, ErrWrongPassword)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(in.GetNewPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	master.Pwd = string(hashedPassword)
	master.PwdExpirationDate = ms.getPasswordExpirationDate()
	if err := ms.masterRepo.Update(master); err != nil {
		return nil, err
	}

	return &pb.UpdateMasterResponse{
		OK: true,
	}, nil

}

// return now + 30 days
func (ms *MasterService) getPasswordExpirationDate() time.Time {
	return time.Now().AddDate(-1, 0, 30)
}

func isValidCreateMasterRequest(request *pb.CreateMasterRequest) bool {
	return len(request.GetEmail()) > 0 && len(request.GetPassword()) > 0
}

func isValidteAuthMasterRequest(request *pb.AuthMasterRequest) bool {
	return len(request.GetEmail()) > 0 && len(request.GetPassword()) > 0
}

func isValidUpdateMasterRequest(request *pb.UpdateMasterRequest) bool {
	return len(request.GetEmail()) > 0 && len(request.GetOldPassword()) > 0 && len(request.GetNewPassword()) > 0

}
