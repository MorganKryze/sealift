package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/MorganKryze/sealift/internal/policy"
	"github.com/MorganKryze/sealift/internal/tools"
)

// logoPolicy keeps a script in an SVG logo from running when its address is
// opened directly: nothing loads, inline styles still draw, and the
// document runs sandboxed.
const logoPolicy = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

// GetInstance reports the deployment mode, what the start has prepared, the
// policy, the brand and the tool versions on the data volume.
func (h *Handlers) GetInstance(ctx context.Context, _ GetInstanceRequestObject) (GetInstanceResponseObject, error) {
	state := h.Ready.State()
	in := Instance{
		Ephemeral: h.Ephemeral > 0,
		Ready:     state.Ready,
		Preparing: make([]PreparingItem, len(state.Items)),
		Brand:     brandToAPI(h.Policy.Brand),
		Policy: Policy{
			Target:              targetToAPI(h.Policy.Settings.Target),
			PipTarget:           pipTargetToAPI(h.Policy.Pip),
			MinReleaseAgeDays:   h.Policy.Settings.MinReleaseAgeDays,
			ResolveParallelism:  h.Policy.Settings.ResolveParallelism,
			DownloadParallelism: h.Policy.Settings.DownloadParallelism,
			Review: ReviewPolicy{
				ProposeOtherMajors: h.Policy.Review.ProposeOtherMajors,
				MajorJump:          ReviewRule(h.Policy.Review.MajorJump),
				CveWithoutFix:      ReviewRule(h.Policy.Review.CVEWithoutFix),
			},
		},
	}
	if in.Ephemeral {
		minutes := int(h.Ephemeral / time.Minute)
		in.IdleMinutes = &minutes
	}
	if state.Warning != "" {
		in.Warning = &state.Warning
	}
	for i, it := range state.Items {
		in.Preparing[i] = preparingItemToAPI(it)
	}
	in.Tools = h.toolVersions(ctx)
	return GetInstance200JSONResponse(in), nil
}

// GetInstanceLogo serves the logo the policy file names, as read at start.
func (h *Handlers) GetInstanceLogo(_ context.Context, _ GetInstanceLogoRequestObject) (GetInstanceLogoResponseObject, error) {
	b := h.Policy.Brand
	headers := GetInstanceLogo200ResponseHeaders{ContentSecurityPolicy: logoPolicy, XContentTypeOptions: "nosniff"}
	size := int64(len(b.Logo))
	switch b.LogoType {
	case "image/png":
		return GetInstanceLogo200ImagepngResponse{Body: bytes.NewReader(b.Logo), Headers: headers, ContentLength: size}, nil
	case "image/svg+xml":
		return GetInstanceLogo200ImagesvgXmlResponse{Body: bytes.NewReader(b.Logo), Headers: headers, ContentLength: size}, nil
	}
	return GetInstanceLogo404ApplicationProblemPlusJSONResponse{ProblemApplicationProblemPlusJSONResponse(NewProblem(http.StatusNotFound, "instance logo", "the policy names no logo"))}, nil
}

// toolVersions reads the versions on the data volume. A folder it cannot
// read lists no version and is logged: the answer still carries the
// preparation and the deployment mode, which matter more.
func (h *Handlers) toolVersions(ctx context.Context) InstanceTools {
	pinned, date := h.Tools.Scanner()
	out := InstanceTools{Trivy: pinned, Pnpm: []string{}, Uv: []string{}}
	if !date.IsZero() {
		out.TrivyDbDate = &date
	}
	if pnpm, err := h.Tools.InstalledPnpm(); err != nil {
		slog.WarnContext(ctx, "api: instance: reading the pnpm versions", "error", err)
	} else {
		out.Pnpm = orEmpty(pnpm)
	}
	if uv, err := h.Tools.InstalledUv(); err != nil {
		slog.WarnContext(ctx, "api: instance: reading the uv versions", "error", err)
	} else {
		out.Uv = orEmpty(uv)
	}
	return out
}

func preparingItemToAPI(it tools.Item) PreparingItem {
	out := PreparingItem{Name: PreparingItemName(it.Name), State: PreparingItemState(it.State)}
	if it.Version != "" {
		out.Version = &it.Version
	}
	if it.Reason != "" {
		out.Reason = &it.Reason
	}
	if !it.NextTry.IsZero() {
		out.NextTry = &it.NextTry
	}
	return out
}

func brandToAPI(b policy.Brand) Brand {
	out := Brand{Name: b.Name, Online: b.Online, Offline: b.Offline, ReviewWord: b.ReviewWord, Logo: len(b.Logo) > 0}
	if b.Accent != "" {
		out.Accent = &b.Accent
	}
	if b.Contact != nil {
		out.Contact = &Contact{Label: b.Contact.Label, Url: b.Contact.URL}
	}
	return out
}
