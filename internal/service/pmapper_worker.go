package service

import (
	"errors"

	"github.com/hibiken/asynq"
)

// RegisterPMapperGraphTaskHandler adds the PMapper handler to an Asynq mux.
// The supplied mux can also register the application's other worker tasks.
func RegisterPMapperGraphTaskHandler(
	mux *asynq.ServeMux,
	graphService *PMapperGraphService,
) error {
	if mux == nil {
		return errors.New("Asynq task mux must not be nil")
	}
	if graphService == nil {
		return errors.New("PMapper graph service must not be nil")
	}
	mux.HandleFunc(PMapperGraphTaskType, graphService.HandlePMapperGraphTask)
	return nil
}
