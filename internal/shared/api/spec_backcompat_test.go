package api

import (
	"encoding/json"
	"testing"
)

// A spec stored before answer_mode/max_response/cname existed decodes with those fields'
// defaults, and still validates. A partial speed_check section keeps the other fields at
// their defaults (§6.11 back-compat).
func TestBackCompatDecode(t *testing.T) {
	raw, err := json.Marshal(DefaultConfigSpec())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "cname")
	delete(m, "speed_check")
	delete(m, "tproxy") // a pre-TProxy spec has no section at all
	old, _ := json.Marshal(m)

	var s ConfigSpec
	if err := json.Unmarshal(old, &s); err != nil {
		t.Fatal(err)
	}
	if s.SpeedCheck.AnswerMode != AnswerModeFastestIP {
		t.Errorf("missing speed_check: answer_mode = %q, want %q", s.SpeedCheck.AnswerMode, AnswerModeFastestIP)
	}
	if s.SpeedCheck.Mode != DefaultSpeedCheckMode || s.SpeedCheck.MaxReplyIPNum != 8 {
		t.Errorf("missing speed_check: %+v, want the default section", s.SpeedCheck)
	}
	if s.CName.Enabled || len(s.CName.Rules) != 0 {
		t.Errorf("missing cname: %+v, want disabled", s.CName)
	}
	if s.Listen.TProxy.EffectiveMode() != TProxyModeRedirect {
		t.Errorf("missing tproxy mode = %q, want redirect", s.Listen.TProxy.EffectiveMode())
	}
	if err := s.Validate(); err != nil {
		t.Errorf("spec without the newer sections must validate: %v", err)
	}

	var ps ConfigSpec
	if err := json.Unmarshal([]byte(`{"speed_check":{"mode":"ping"}}`), &ps); err != nil {
		t.Fatal(err)
	}
	if ps.SpeedCheck.Mode != "ping" {
		t.Errorf("mode = %q, want ping", ps.SpeedCheck.Mode)
	}
	if ps.SpeedCheck.AnswerMode != AnswerModeFastestIP {
		t.Errorf("partial speed_check: answer_mode = %q", ps.SpeedCheck.AnswerMode)
	}
	if ps.SpeedCheck.MaxResponse != 0 || ps.SpeedCheck.MaxReplyIPNum != 8 {
		t.Errorf("partial speed_check lost defaults: %+v", ps.SpeedCheck)
	}
}

func TestNewFieldValidation(t *testing.T) {
	bad := func(name string, mut func(*ConfigSpec)) {
		t.Helper()
		s := DefaultConfigSpec()
		mut(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	bad("answer_mode", func(s *ConfigSpec) { s.SpeedCheck.AnswerMode = "fastest-nonsense" })
	bad("max_response", func(s *ConfigSpec) { s.SpeedCheck.MaxResponse = 65 })
	bad("cname.name", func(s *ConfigSpec) {
		s.CName = CNames{Enabled: true, Rules: []CNameRule{{Name: "not a name", Target: "x.example"}}}
	})
	bad("cname.target", func(s *ConfigSpec) {
		s.CName = CNames{Enabled: true, Rules: []CNameRule{{Name: "x.example", Target: "bad name"}}}
	})
	ok := DefaultConfigSpec()
	ok.SpeedCheck.AnswerMode, ok.SpeedCheck.MaxResponse = AnswerModeFastestResponse, 64
	ok.CName = CNames{Enabled: true, Rules: []CNameRule{{Name: "Mirror.Example.Com.", Target: "fast.example.net"}}}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid values rejected: %v", err)
	}
}
