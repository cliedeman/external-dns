/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"github.com/chiefy/linodego"
	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestNewLinodeProvider(t *testing.T) {
	_ = os.Setenv("LINODE_TOKEN", "xxxxxxxxxxxxxxxxx")
	_, err := NewLinodeProvider(NewDomainFilter([]string{"ext-dns-test.zalando.to."}), true)
	if err != nil {
		t.Errorf("should not fail, %s", err)
	}
	_ = os.Unsetenv("LINODE_TOKEN")
	_, err = NewLinodeProvider(NewDomainFilter([]string{"ext-dns-test.zalando.to."}), true)
	if err == nil {
		t.Errorf("expected to fail")
	}
}

func TestLinodeStripRecordName(t *testing.T) {
	assert.Equal(t, "api", getStrippedRecordName(&linodego.Domain{
		Domain: "example.com",
	}, &endpoint.Endpoint{
		DNSName: "api.example.com",
	}))

	assert.Equal(t, "", getStrippedRecordName(&linodego.Domain{
		Domain: "example.com",
	}, &endpoint.Endpoint{
		DNSName: "example.com",
	}))
}
