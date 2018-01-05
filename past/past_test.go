package past

import "testing"

func TestPAE(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{[]string{}, `\x00\x00\x00\x00\x00\x00\x00\x00`},
		{[]string{""}, `\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`},
		{[]string{"test"}, `\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test`},
	}

	for _, test := range tests {
		got := string(pae(test.input...))

		if got != test.want {
			t.Errorf("incorrect value for %q, wanted=%q, got=%q", test.input, test.want, got)
		}
	}
}
