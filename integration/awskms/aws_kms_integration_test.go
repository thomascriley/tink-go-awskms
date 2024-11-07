// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awskms

import (
	"bytes"
	"context"
	"testing"

	// context is used to cancel outstanding requests

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	keyPrefix   = "aws-kms://arn:aws:kms:us-east-2:235739564943:"
	keyAliasURI = "aws-kms://arn:aws:kms:us-east-2:235739564943:alias/unit-and-integration-testing"
	keyURI      = "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	keyURI2     = "aws-kms://arn:aws:kms:us-east-2:235739564943:key/b3ca2efd-a8fb-47f2-b541-7e20f8c5cd11"
)

const (
	credCSVFile = "testdata/aws/credentials.csv"
	credINIFile = "testdata/aws/credentials.ini"
)

func TestNewClientWithCredentialsGetAEADEncryptDecrypt(t *testing.T) {
	credFilePath := testFilePath(t, credCSVFile)
	client, err := NewClientWithOptions(context.Background(), keyURI, WithCredentialPath(credFilePath))
	if err != nil {
		t.Fatalf("error setting up AWS client: %v", err)
	}
	a, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(keyURI) err = %v, want nil", err)
	}
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	gotPlaintext, err := a.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("a.Decrypt() = %q, want %q", gotPlaintext, plaintext)
	}

	invalidAssociatedData := []byte("invalidAssociatedData")
	_, err = a.Decrypt(ciphertext, invalidAssociatedData)
	if err == nil {
		t.Error("a.Decrypt(ciphertext, invalidAssociatedData) err = nil, want error")
	}
}

func TestEmptyAssociatedDataEncryptDecrypt(t *testing.T) {
	credFilePath := testFilePath(t, credCSVFile)
	client, err := NewClientWithOptions(context.Background(), keyURI, WithCredentialPath(credFilePath))
	if err != nil {
		t.Fatalf("error setting up AWS client: %v", err)
	}
	a, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(keyURI) err = %v, want nil", err)
	}
	plaintext := []byte("plaintext")
	emptyAssociatedData := []byte{}
	ciphertext, err := a.Encrypt(plaintext, emptyAssociatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, emptyAssociatedData) err = %v, want nil", err)
	}
	gotPlaintext, err := a.Decrypt(ciphertext, emptyAssociatedData)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("a.Decrypt() = %q, want %q", gotPlaintext, plaintext)
	}

	gotPlaintext2, err := a.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext, nil) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext2, plaintext) {
		t.Errorf("a.Decrypt() = %q, want %q", gotPlaintext, plaintext)
	}
}

func TestKeyCommitment(t *testing.T) {
	credFilePath := testFilePath(t, credCSVFile)
	client, err := NewClientWithOptions(context.Background(), keyPrefix, WithCredentialPath(credFilePath))
	if err != nil {
		t.Fatalf("error setting up AWS client: %v", err)
	}

	// Create AEAD primitives for two keys.
	keys := []string{keyURI, keyURI2}
	aeads := make([]tink.AEAD, 0, len(keys))
	for _, k := range keys {
		a, err := client.GetAEAD(k)
		if err != nil {
			t.Fatalf("client.GetAEAD(keyURI) err = %v, want nil", err)
		}
		aeads = append(aeads, a)
	}

	// Create a ciphertext using the first primitive.
	plaintext := []byte("plaintext")
	associatedData := []byte("associated data")
	ciphertext, err := aeads[0].Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("aeads[0].Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	gotPlaintext, err := aeads[0].Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("aeads[0].Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("aeads[0].Decrypt() = %q, want %q", gotPlaintext, plaintext)
	}

	// Attempt to decrypt using the other primitive.
	_, err = aeads[1].Decrypt(ciphertext, associatedData)
	if err == nil {
		t.Fatalf("aeads[1].Decrypt(ciphertext, associatedData) err = nil, want non-nil")
	}
}

func TestKMSEnvelopeAEADEncryptAndDecrypt(t *testing.T) {
	for _, credFile := range []string{credCSVFile, credINIFile} {
		credFilePath := testFilePath(t, credFile)
		client, err := NewClientWithOptions(context.Background(), keyURI, WithCredentialPath(credFilePath))

		if err != nil {
			t.Fatalf("NewClientWithOptions() err = %q, want nil", err)
		}

		kekAEAD, err := client.GetAEAD(keyURI)
		if err != nil {
			t.Fatalf("client.GetAEAD(keyURI) err = %q, want nil", err)
		}

		dekTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
		a := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
		plaintext := []byte("plaintext")
		for _, associatedData := range [][]byte{nil, []byte("associated data")} {
			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(plaintext, associatedData) err = %q, want nil", err)
			}
			gotPlaintext, err := a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
			}
			if !bytes.Equal(gotPlaintext, plaintext) {
				t.Errorf("a.Decrypt() = %q, want %q", gotPlaintext, plaintext)
			}
		}
	}
}
