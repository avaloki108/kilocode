// kilocode_change - new file: Storybook story for Release Notes Modal component
import type { Meta, StoryObj } from "@storybook/react-vite"
import { ReleaseNotesModal } from "@/components/release-notes/ReleaseNotesModal"
import { sampleReleaseNotes } from "./sampleReleaseNotes"

const meta = {
	title: "Components/ReleaseNotesModal",
	component: ReleaseNotesModal,
	argTypes: {
		isOpen: {
			control: { type: "boolean" },
		},
		currentVersion: {
			control: { type: "text" },
		},
		lastViewedVersion: {
			control: { type: "text" },
		},
	},
	parameters: {
		disableChromaticDualThemeSnapshot: true,
	},
	args: {
		isOpen: true,
		currentVersion: "4.106.0",
		releaseNotes: sampleReleaseNotes,
		lastViewedVersion: "4.104.0",
		onClose: () => console.log("Modal closed"),
		onVersionViewed: (version: string) => console.log("Version viewed:", version),
	},
} satisfies Meta<typeof ReleaseNotesModal>

export default meta
type Story = StoryObj<typeof meta>

export const Default: Story = {
	args: {
		releaseNotes: sampleReleaseNotes,
		lastViewedVersion: "4.104.0",
	},
}

export const SingleRelease: Story = {
	args: {
		releaseNotes: [sampleReleaseNotes[0]],
	},
}

export const UncategorizedChanges: Story = {
	args: {
		currentVersion: "4.104.0",
		releaseNotes: [sampleReleaseNotes[2]], // The one with only rawChanges
	},
}
