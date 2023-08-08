package errdet

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BadRequest creates a new BadRequest error with the given message and field violations.
func BadRequest(msg string, violations ...*errdetails.BadRequest_FieldViolation) error {
	s := status.New(codes.InvalidArgument, msg)
	ds, err := s.WithDetails(&errdetails.BadRequest{
		FieldViolations: violations,
	})
	if err != nil {
		return s.Err()
	}
	return ds.Err()
}


// AlreadyExists creates a new AlreadyExists error with the given message and field violations.
func AlreadyExists(msg string, violations ...*errdetails.BadRequest_FieldViolation) error {
	s := status.New(codes.AlreadyExists, msg)
	ds, err := s.WithDetails(&errdetails.BadRequest{
		FieldViolations: violations,
	})
	if err != nil {
		return s.Err()
	}
	return ds.Err()
}