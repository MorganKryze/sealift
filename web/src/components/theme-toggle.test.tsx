import { fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it } from "vitest"

import { ThemeToggle } from "./theme-toggle"

afterEach(() => {
  localStorage.clear()
  document.documentElement.classList.remove("light", "dark")
})

const thumb = (group: HTMLElement) => group.querySelector<HTMLElement>("[data-thumb]")

describe("theme toggle", () => {
  it("offers System, Light and Dark as one radio group with one checked", () => {
    render(<ThemeToggle />)
    const group = screen.getByRole("radiogroup", { name: "Theme" })
    const radios = within(group).getAllByRole("radio")
    expect(radios.map((r) => r.textContent)).toEqual(["System", "Light", "Dark"])
    expect(radios.filter((r) => r.getAttribute("aria-checked") === "true")).toHaveLength(1)
    expect(radios.filter((r) => r.tabIndex === 0)).toHaveLength(1)
  })

  it("moves the pick with the arrow keys", () => {
    render(<ThemeToggle />)
    const group = screen.getByRole("radiogroup", { name: "Theme" })
    fireEvent.keyDown(screen.getByRole("radio", { name: "System" }), { key: "ArrowRight" })
    expect(screen.getByRole("radio", { name: "Light" })).toBeChecked()
    expect(screen.getByRole("radio", { name: "Light" })).toHaveFocus()
    fireEvent.keyDown(group, { key: "ArrowLeft" })
    fireEvent.keyDown(group, { key: "ArrowLeft" })
    expect(screen.getByRole("radio", { name: "Dark" })).toBeChecked()
    expect(document.documentElement.classList.contains("dark")).toBe(true)
  })

  it("stores the pick and sets the class", () => {
    render(<ThemeToggle />)
    fireEvent.click(screen.getByRole("radio", { name: "Dark" }))
    expect(localStorage.getItem("sealift-theme")).toBe("dark")
    expect(document.documentElement.classList.contains("dark")).toBe(true)
    expect(screen.getByRole("radio", { name: "Dark" })).toBeChecked()
    fireEvent.click(screen.getByRole("radio", { name: "Light" }))
    expect(localStorage.getItem("sealift-theme")).toBe("light")
    expect(document.documentElement.classList.contains("light")).toBe(true)
    expect(document.documentElement.classList.contains("dark")).toBe(false)
  })

  it("follows the system when nothing is stored", () => {
    render(<ThemeToggle />)
    expect(screen.getByRole("radio", { name: "System" })).toBeChecked()
    expect(document.documentElement.classList.contains("light")).toBe(false)
    expect(document.documentElement.classList.contains("dark")).toBe(false)
  })

  it("starts on the stored pick", () => {
    localStorage.setItem("sealift-theme", "light")
    render(<ThemeToggle />)
    expect(screen.getByRole("radio", { name: "Light" })).toBeChecked()
  })

  it("moves the thumb with a transform", () => {
    render(<ThemeToggle />)
    const group = screen.getByRole("radiogroup", { name: "Theme" })
    expect(thumb(group)?.style.transform).toBe("translateX(0%)")
    fireEvent.click(screen.getByRole("radio", { name: "Dark" }))
    expect(thumb(group)?.style.transform).toBe("translateX(200%)")
    expect(thumb(group)?.className).toMatch(/\btransition-transform\b/)
    expect(thumb(group)?.style.left).toBe("")
    expect(thumb(group)?.className).not.toMatch(/transition-(all|\[left)/)
  })
})
