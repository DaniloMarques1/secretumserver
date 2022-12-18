package service

import (
	"context"
	"errors"
	"time"

	"github.com/danilomarques1/secretumserver/model"
	"github.com/danilomarques1/secretumserver/pb"
	"github.com/google/uuid"
)

var (
	ValidationError = errors.New("Error validating request body")
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

    masterPwdExpiration := time.Now().AddDate(0, 0, 30)

    master := &model.Master{
        Id: uuid.NewString(),
        Email: in.GetEmail(),
        Pwd: in.GetPassword(),
        PwdExpirationDate: masterPwdExpiration,
    }

    if err := ms.repository.Save(master); err != nil {
        return nil, err
    }

	return &pb.CreateMasterResponse{
        OK: true,
    }, nil
}

func validateCreateMasterRequest(request *pb.CreateMasterRequest) error {
	if len(request.GetEmail()) > 0 && len(request.GetPassword()) > 0 {
		return nil
	}

	return ValidationError
}
