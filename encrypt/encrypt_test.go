package encrypt

import (
	"testing"
)

// hold back the river let me look in your eyes

func TestEncrypt(t *testing.T) {
	t.Setenv("ENCRYPT_KEY", "6e66874eb3a6ef35fc679243707ef8c425ce6f7267ab367d33583d9a789f7a3d")
	cases := []struct {
		label    string
		input    string
		expected string
	}{
		{"Should return the correct output 1", "This will be secured", "This will be secured"},
		{"Should return the correct output 2", "hold back the river let me look in your eyes", "hold back the river let me look in your eyes"},
		{"Should return the correct output 3", "the encrypt plain text", "the encrypt plain text"},
		{"Should return the correct output 4", "Everybody's got their dues in life to pay, oh, oh, oh I know nobody knows Where it comes and where it goes I know it's everybody's sin You got to lose to know how to win", "Everybody's got their dues in life to pay, oh, oh, oh I know nobody knows Where it comes and where it goes I know it's everybody's sin You got to lose to know how to win"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			e, err := NewEncrypt(tc.input)
			if err != nil {
				t.Fatalf("Err should when creating be nil %v\n", err)
			}

			crypted, err := e.EncryptMessage()
			if err != nil {
				t.Fatalf("Err should when encrypting be nil %v\n", err)
			}

			d, err := NewDecrypt(crypted)
			if err != nil {
				t.Fatalf("Err should when decrypting be nil %v\n", err)
			}

			decrypted, err := d.DecryptMessage()
			if err != nil {
				t.Fatalf("Err should when decrypting be nil %v\n", err)
			}

			if decrypted != tc.expected {
				t.Fatalf("Wrong output expected %v(%v) got %v(%v)\n", tc.expected, len(tc.expected), decrypted, len(decrypted))
			}

		})
	}
}
