package bfsisim

import (
	"encoding/json"
	"net/http"
)

// Identity is one synthetic directory entry for the reconnaissance scenarios. Values are fixed and
// obviously fake; nothing here is drawn from a real directory.
type Identity struct {
	SAM         string `json:"sam"`
	DisplayName string `json:"displayName"`
	Department  string `json:"department"`
}

var syntheticIdentities = []Identity{
	{SAM: "bas-sim-jdoe", DisplayName: "Jordan Doe (synthetic)", Department: "Retail Banking"},
	{SAM: "bas-sim-asmith", DisplayName: "Alex Smith (synthetic)", Department: "Treasury"},
	{SAM: "bas-sim-rkhan", DisplayName: "Riya Khan (synthetic)", Department: "Payments"},
	{SAM: "bas-sim-mlopez", DisplayName: "Miguel Lopez (synthetic)", Department: "Risk"},
	{SAM: "bas-sim-tnguyen", DisplayName: "Taylor Nguyen (synthetic)", Department: "Compliance"},
	{SAM: "bas-sim-ebrown", DisplayName: "Eli Brown (synthetic)", Department: "IT Operations"},
}

func identitiesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(syntheticIdentities)
}
