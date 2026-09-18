package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/MorganKryze/sealift/internal/jobs"
)

// QueueExport queues an export of one analysis with a version selection.
func (h *Handlers) QueueExport(_ context.Context, req QueueExportRequestObject) (QueueExportResponseObject, error) {
	if req.Body == nil {
		return QueueExportdefaultApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest, "queue export", errors.New("an export request body is required"))), nil
	}
	body := *req.Body
	jobsReq := jobs.ExportRequest{
		Selection:      body.Selection,
		IncludeProject: body.IncludeProject != nil && *body.IncludeProject,
	}
	info, err := h.Service.QueueExport(req.ProjectId, req.AnalysisId, jobsReq)
	if err != nil {
		var invalid *jobs.ErrInvalidSelection
		if errors.As(err, &invalid) {
			return QueueExportdefaultApplicationProblemPlusJSONResponse(invalidSelectionProblem(invalid.Bad)), nil
		}
		return QueueExportdefaultApplicationProblemPlusJSONResponse(autoProblem("queue export", err)), nil
	}
	return QueueExport202JSONResponse(exportToAPI(info)), nil
}

// GetExport returns an export's status and files. A queued or running
// export has no committed directory yet, so this checks Service's live
// tracking before falling back to the store.
func (h *Handlers) GetExport(_ context.Context, req GetExportRequestObject) (GetExportResponseObject, error) {
	if state, ok := h.Service.LiveState(req.ProjectId, "export", req.ExportId); ok {
		createdAt, _ := time.Parse(idLayout, req.ExportId)
		return GetExport200JSONResponse(Export{
			Id: req.ExportId, ProjectId: req.ProjectId, State: State(state), CreatedAt: createdAt,
		}), nil
	}
	info, err := h.Store.ExportInfo(req.ProjectId, req.ExportId)
	if err != nil {
		return GetExportdefaultApplicationProblemPlusJSONResponse(autoProblem("get export", err)), nil
	}
	return GetExport200JSONResponse(exportToAPI(info)), nil
}

// DeleteExport removes a committed export.
func (h *Handlers) DeleteExport(_ context.Context, req DeleteExportRequestObject) (DeleteExportResponseObject, error) {
	if err := h.Store.DeleteExport(req.ProjectId, req.ExportId); err != nil {
		return DeleteExportdefaultApplicationProblemPlusJSONResponse(autoProblem("delete export", err)), nil
	}
	return DeleteExport204Response{}, nil
}

// DownloadExportFile streams one file of a finished export.
func (h *Handlers) DownloadExportFile(_ context.Context, req DownloadExportFileRequestObject) (DownloadExportFileResponseObject, error) {
	f, err := h.Store.ExportFile(req.ProjectId, req.ExportId, req.Name)
	if err != nil {
		return DownloadExportFiledefaultApplicationProblemPlusJSONResponse(autoProblem("download export file", err)), nil
	}
	var size int64
	if st, statErr := f.Stat(); statErr == nil {
		size = st.Size()
	}
	return DownloadExportFile200ApplicationoctetStreamResponse{Body: f, ContentLength: size}, nil
}
