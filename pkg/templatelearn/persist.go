package templatelearn

import (
	"encoding/json"
	"os"
)

// StoreData is the JSON-serializable store state
type StoreData struct {
	Feedback     []*Feedback        `json:"feedback"`
	Suppressions []*SuppressionRule `json:"suppressions"`
}

// Save persists the store to disk
func (s *FeedbackStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := StoreData{
		Feedback:     make([]*Feedback, 0, len(s.feedback)),
		Suppressions: make([]*SuppressionRule, 0, len(s.suppressions)),
	}
	for _, fb := range s.feedback {
		data.Feedback = append(data.Feedback, fb)
	}
	for _, rule := range s.suppressions {
		data.Suppressions = append(data.Suppressions, rule)
	}

	file, err := os.Create(s.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// Load reads the store from disk
func (s *FeedbackStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no file = empty store
		}
		return err
	}
	defer file.Close()

	var data StoreData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return err
	}

	s.feedback = make(map[string]*Feedback)
	s.suppressions = make(map[string]*SuppressionRule)

	for _, fb := range data.Feedback {
		s.feedback[fb.ID] = fb
	}
	for _, rule := range data.Suppressions {
		s.suppressions[rule.ID] = rule
	}

	return nil
}
