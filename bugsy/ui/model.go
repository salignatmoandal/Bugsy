package ui

import tea "github.com/charmbracelet/bubbletea"

type model struct {
	state  string
	output string
}

// Init implements tea.Model.
func (m model) Init() tea.Cmd {
	panic("unimplemented")
}

// Update implements tea.Model.
func (m model) Update(tea.Msg) (tea.Model, tea.Cmd) {
	panic("unimplemented")
}

// View implements tea.Model.
func (m model) View() string {
	panic("unimplemented")
}

func InitialModel() model {
	return model{
		state:  "input",
		output: "",
	}
}
