package service

import (
	"context"
	"log"
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
		log.Printf("Error creating master service %v\n", err)
		return nil, err
	}

	return &MasterService{
		masterRepo: masterRepo,
	}, nil
}

func (ms *MasterService) SaveMaster(ctx context.Context, in *pb.CreateMasterRequest) (*pb.CreateMasterResponse, error) {
	if !isValidCreateMasterRequest(in) {
		log.Printf("Error validating create master request\n")
		return nil, status.Errorf(
			codes.InvalidArgument,
			ErrValidation,
		)
	}

	if _, err := ms.masterRepo.FindByEmail(in.GetEmail()); err == nil {
		log.Printf("There was a master registered with the given email already\n")
		return nil, status.Errorf(
			codes.AlreadyExists,
			ErrEmailAlreadyUsed,
		)
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(in.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing master password %v\n", err)
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
		log.Printf("Error saving password %v\n", err)
		return nil, err
	}

	return &pb.CreateMasterResponse{
		OK: true,
	}, nil
}

func (ms *MasterService) AuthenticateMaster(ctx context.Context, in *pb.AuthMasterRequest) (*pb.AuthMasterResponse, error) {
	if !isValidteAuthMasterRequest(in) {
		log.Printf("Error validating auth request\n")
		return nil, status.Errorf(
			codes.InvalidArgument,
			ErrValidation,
		)
	}

	master, err := ms.masterRepo.FindByEmail(in.GetEmail())
	if err != nil {
		log.Printf("Error finding master by email %v\n", err)
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(master.Pwd), []byte(in.GetPassword())); err != nil {
		log.Printf("Error comparing master password %v\n", err)
		return nil, status.Errorf(codes.NotFound, ErrWrongPassword)
	}

	// by returning PermissionDenied the client will interpret it
	// as needing to update the password
	if master.PwdExpirationDate.Unix() <= time.Now().Unix() {
		log.Printf("master password has expired\n")
		return nil, status.Errorf(
			codes.PermissionDenied,
			ErrPasswordExpired,
		)
	}

	tokenResponse, err := token.GetToken(master.Id)
	if err != nil {
		log.Printf("Error getting token %v\n", err)
		return nil, err
	}

	return &pb.AuthMasterResponse{
		AccessToken:  tokenResponse.AccessToken,
		ExpiresIn:    tokenResponse.ExpiresIn,
		RefreshToken: tokenResponse.RefreshToken,
	}, nil
}

func (ms *MasterService) UpdateMaster(ctx context.Context, in *pb.UpdateMasterRequest) (*pb.UpdateMasterResponse, error) {
	if !isValidUpdateMasterRequest(in) {
		log.Printf("Error validating update request\n")
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}
	master, err := ms.masterRepo.FindByEmail(in.GetEmail())
	if err != nil {
		log.Printf("Error finding master %v\n", err)
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(master.Pwd), []byte(in.GetOldPassword())); err != nil {
		log.Printf("Error comparing master password %v\n", err)
		return nil, status.Errorf(codes.NotFound, ErrWrongPassword)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(in.GetNewPassword()), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing master password %v\n", err)
		return nil, err
	}
	master.Pwd = string(hashedPassword)
	master.PwdExpirationDate = ms.getPasswordExpirationDate()
	if err := ms.masterRepo.Update(master); err != nil {
		log.Printf("Error updating master password\n")
		return nil, err
	}

	return &pb.UpdateMasterResponse{
		OK: true,
	}, nil

}

func (ms *MasterService) RefreshMasterToken(ctx context.Context, in *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	if len(in.GetRefreshToken()) == 0 {
		log.Printf("Error validating refresh token request\n")
		return nil, status.Errorf(codes.InvalidArgument, ErrValidation)
	}

	claims, err := token.ValidateRefreshToken(in.GetRefreshToken())
	if err != nil {
		return nil, err
	}

	tokenResponse, err := token.GetToken(claims.MasterId)
	if err != nil {
		return nil, err
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  tokenResponse.AccessToken,
		ExpiresIn:    tokenResponse.ExpiresIn,
		RefreshToken: tokenResponse.RefreshToken,
	}, nil
}

// return now + 30 days
func (ms *MasterService) getPasswordExpirationDate() time.Time {
	return time.Now().AddDate(0, 0, 30)
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
