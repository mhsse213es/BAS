package scim

// UserRow is the subset of an Audspect users row needed to build a SCIM
// User resource — the only place SCIM's schema and Audspect's users table
// meet.
type UserRow struct {
	ID        string
	Username  string
	Active    bool
	CreatedAt string
	UpdatedAt string
}

// FromUserRow builds the outgoing SCIM User wire shape for one users row.
// Audspect's username doubles as the user's email — SCIM's userName and
// primary email are both set from it.
func FromUserRow(row UserRow) User {
	return User{
		Schemas:  []string{SchemaUser},
		ID:       row.ID,
		UserName: row.Username,
		Active:   row.Active,
		Emails:   []Email{{Value: row.Username, Primary: true}},
		Meta: &Meta{
			ResourceType: "User",
			Created:      row.CreatedAt,
			LastModified: row.UpdatedAt,
		},
	}
}
