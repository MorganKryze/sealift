package api

import (
	"context"
	"errors"
	"time"

	"github.com/MorganKryze/sealift/internal/store"
)

// idLayout is the time.Parse layout analysis and export IDs use: a UTC
// timestamp with second precision (spec section 3), the same one
// internal/store and internal/jobs parse and format it with.
const idLayout = "20060102T150405Z"

// QueueAnalysis queues an analysis for the project.
func (h *Handlers) QueueAnalysis(_ context.Context, req QueueAnalysisRequestObject) (QueueAnalysisResponseObject, error) {
	info, err := h.Service.QueueAnalysis(req.ProjectId)
	if err != nil {
		return QueueAnalysisdefaultApplicationProblemPlusJSONResponse(autoProblem("queue analysis", err)), nil
	}
	return QueueAnalysis202JSONResponse(analysisToAPI(info)), nil
}

// GetAnalysis returns an analysis' status and results. A queued or
// running analysis has no committed directory yet, so this checks
// Service's live tracking before falling back to the store.
func (h *Handlers) GetAnalysis(_ context.Context, req GetAnalysisRequestObject) (GetAnalysisResponseObject, error) {
	if state, ok := h.Service.LiveState(req.ProjectId, "analysis", req.AnalysisId); ok {
		createdAt, _ := time.Parse(idLayout, req.AnalysisId)
		return GetAnalysis200JSONResponse(Analysis{
			Id: req.AnalysisId, ProjectId: req.ProjectId, State: State(state), CreatedAt: createdAt,
		}), nil
	}
	info, err := h.Store.AnalysisInfo(req.ProjectId, req.AnalysisId)
	if err != nil {
		return GetAnalysisdefaultApplicationProblemPlusJSONResponse(autoProblem("get analysis", err)), nil
	}
	return GetAnalysis200JSONResponse(analysisToAPI(info)), nil
}

// DeleteAnalysis removes a committed analysis.
func (h *Handlers) DeleteAnalysis(_ context.Context, req DeleteAnalysisRequestObject) (DeleteAnalysisResponseObject, error) {
	if err := h.Store.DeleteAnalysis(req.ProjectId, req.AnalysisId); err != nil {
		return DeleteAnalysisdefaultApplicationProblemPlusJSONResponse(autoProblem("delete analysis", err)), nil
	}
	return DeleteAnalysis204Response{}, nil
}

// CancelAnalysis cancels a running or queued analysis. Once Service is no
// longer tracking the id, either the job already ended or it never
// existed; the store, not Service, has the last word at that point.
func (h *Handlers) CancelAnalysis(_ context.Context, req CancelAnalysisRequestObject) (CancelAnalysisResponseObject, error) {
	err := h.Service.Cancel(req.ProjectId, "analysis", req.AnalysisId)
	if err == nil {
		createdAt, _ := time.Parse(idLayout, req.AnalysisId)
		return CancelAnalysis200JSONResponse(Analysis{
			Id: req.AnalysisId, ProjectId: req.ProjectId, State: Cancelled, CreatedAt: createdAt,
		}), nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return CancelAnalysisdefaultApplicationProblemPlusJSONResponse(autoProblem("cancel analysis", err)), nil
	}
	info, infoErr := h.Store.AnalysisInfo(req.ProjectId, req.AnalysisId)
	if infoErr != nil {
		return CancelAnalysisdefaultApplicationProblemPlusJSONResponse(autoProblem("cancel analysis", infoErr)), nil
	}
	return CancelAnalysis200JSONResponse(analysisToAPI(info)), nil
}
