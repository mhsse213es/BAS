package wafbotabuse

import "fmt"

// ValidateBotAbuseCatalog rejects a catalog containing two vectors with
// the same ID. NewBotAbuseVector cannot see sibling entries, so this is
// the single place uniqueness is enforced across a whole catalog
// snapshot.
func ValidateBotAbuseCatalog(vectors []BotAbuseVector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate bot-abuse vector ID %q", v.ID)
		}
		seen[v.ID] = true
	}
	return nil
}
