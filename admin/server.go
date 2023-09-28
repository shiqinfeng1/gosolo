package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pb "gosolo/admin/admin"
)

// 本文件实现的rpc服务的业务逻辑的服务，该服务需通过RegisterAdminServer注册

// adminServer是proto文件中定义的admin服务，在该文件中需要实现proto文件中定义的rpc接口：RunCommand
// adminServer服务依赖于proto文件生成的pb.go文件
type adminServer struct {
	pb.UnimplementedAdminServer
	cr *CommandRunner
}

func (s *adminServer) RunCommand(ctx context.Context, in *pb.RunCommandRequest) (*pb.RunCommandResponse, error) {
	result, err := s.cr.runCommand(ctx, in.GetCommandName(), in.GetData().AsInterface())
	if err != nil {
		return nil, err
	}

	value, err := structpb.NewValue(result)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RunCommandResponse{
		Output: value,
	}, nil
}

// 生成一个新的admin服务实例
func NewAdminServer(cr *CommandRunner) *adminServer {
	return &adminServer{cr: cr}
}
