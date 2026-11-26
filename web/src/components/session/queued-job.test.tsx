import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import type { Analysis, Export, Project } from "@/api/projects";
import { initialAnalysisEventsState } from "@/lib/analysisEvents";

import { ExportScreen } from "./export-screen";

vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
}));
vi.mock("@/hooks/use-job-events", () => ({
  useJobEvents: () => initialAnalysisEventsState,
}));

const project = { id: "p1" } as unknown as Project;
const noop = () => {};

function renderWithClient(ui: ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>,
  );
}

function renderExport(state: string) {
  const analysis = { id: "a1", state: "done" } as unknown as Analysis;
  const relatedExport = { id: "e1", state } as unknown as Export;
  return renderWithClient(
    <ExportScreen
      project={project}
      analysis={analysis}
      relatedExport={relatedExport}
      onChanged={noop}
      onNavigateStep={noop}
    />,
  );
}

describe("a queued export", () => {
  it("says it waits for another job and hides the counters", () => {
    renderExport("queued");
    expect(
      screen.getByRole("heading", { name: "Waiting for another job" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /one job at a time\. This export starts when the one before it ends/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Building the archive" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Packages")).not.toBeInTheDocument();
    expect(screen.queryByText("From cache")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument();
  });

  it("reads as today once running", () => {
    renderExport("running");
    expect(
      screen.getByRole("heading", { name: "Building the archive" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Packages")).toBeInTheDocument();
  });
});

describe("an export cancelled while queued", () => {
  // It never ran: its status.json holds no step, so the server sends no
  // failure and the screen has no step to stop at.
  it("says it was cancelled and offers to start it again", () => {
    renderExport("cancelled");
    expect(
      screen.getByRole("heading", { name: "Export cancelled" }),
    ).toBeInTheDocument();
    expect(screen.getByText("You cancelled this export.")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Start the export again" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Cancel" }),
    ).not.toBeInTheDocument();
  });
});
