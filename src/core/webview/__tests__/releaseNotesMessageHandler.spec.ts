// kilocode_change - new file: Test suite for release notes message handler
import { describe, it, expect, vi, beforeEach } from "vitest"
import { ClineProvider } from "../ClineProvider"

describe("Release Notes Message Handler", () => {
	let provider: ClineProvider
	let mockSetValue: any
	let mockPostStateToWebview: any

	beforeEach(() => {
		mockSetValue = vi.fn()
		mockPostStateToWebview = vi.fn()

		provider = {
			contextProxy: {
				setValue: mockSetValue,
			},
			postStateToWebview: mockPostStateToWebview,
		} as any
	})

	it("should handle updateGlobalState message for release version", async () => {
		const { webviewMessageHandler } = await import("../webviewMessageHandler")

		const message = {
			type: "updateGlobalState" as const,
			key: "lastViewedReleaseVersion",
			stateValue: "4.106.0",
		}

		await webviewMessageHandler(provider, message)

		expect(mockSetValue).toHaveBeenCalledWith("lastViewedReleaseVersion", "4.106.0")
		expect(mockPostStateToWebview).toHaveBeenCalled()
	})

	it("should not update state if no key or stateValue provided", async () => {
		const { webviewMessageHandler } = await import("../webviewMessageHandler")

		const message = {
			type: "updateGlobalState" as const,
		}

		await webviewMessageHandler(provider, message)

		expect(mockSetValue).not.toHaveBeenCalled()
		expect(mockPostStateToWebview).not.toHaveBeenCalled()
	})

	it("should not update state if key is missing", async () => {
		const { webviewMessageHandler } = await import("../webviewMessageHandler")

		const message = {
			type: "updateGlobalState" as const,
			stateValue: "4.106.0",
		}

		await webviewMessageHandler(provider, message)

		expect(mockSetValue).not.toHaveBeenCalled()
		expect(mockPostStateToWebview).not.toHaveBeenCalled()
	})

	it("should not update state if stateValue is undefined", async () => {
		const { webviewMessageHandler } = await import("../webviewMessageHandler")

		const message = {
			type: "updateGlobalState" as const,
			key: "lastViewedReleaseVersion",
			stateValue: undefined,
		}

		await webviewMessageHandler(provider, message)

		expect(mockSetValue).not.toHaveBeenCalled()
		expect(mockPostStateToWebview).not.toHaveBeenCalled()
	})
})
