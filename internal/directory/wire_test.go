package directory

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestAssertionControlOnActualLDAPWire(t *testing.T) {
	revision := "42"
	value := "before"
	var mu sync.Mutex
	serverErrors := make(chan error, 8)
	factory := func(_ context.Context, c Config) (Session, error) {
		if c.Server != "selected-dc" {
			return nil, fmt.Errorf("connection changed DC")
		}
		client, server := net.Pipe()
		server.SetDeadline(time.Now().Add(3 * time.Second))
		go func() {
			defer server.Close()
			serverErrors <- func() error {
				request, e := readLDAP(server)
				if e != nil {
					return e
				}
				if request.Children[1].Tag != ldap.ApplicationSearchRequest {
					return fmt.Errorf("missing same-session supportedControl preflight")
				}
				id := request.Children[0].Value.(int64)
				envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
				entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
				entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
				attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedControl", ""))
				values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
				values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, AssertionOID, ""))
				attribute.AppendChild(values)
				attributes.AppendChild(attribute)
				entry.AppendChild(attributes)
				envelope.AppendChild(entry)
				if _, e = server.Write(envelope.Bytes()); e != nil {
					return e
				}
				if e = reply(server, id, ldap.ApplicationSearchResultDone, 0, nil); e != nil {
					return e
				}
				request, e = readLDAP(server)
				if e != nil {
					return e
				}
				id = request.Children[0].Value.(int64)
				if request.Children[1].Tag != ldap.ApplicationModifyRequest || len(request.Children) != 3 {
					return fmt.Errorf("modify/control not sent")
				}
				controls := request.Children[2]
				if len(controls.Children) != 1 {
					return fmt.Errorf("incorrect control count")
				}
				control := controls.Children[0]
				if len(control.Children) != 3 || control.Children[0].Value != AssertionOID || control.Children[1].Value != true {
					return fmt.Errorf("assertion criticality/OID not on wire")
				}
				mu.Lock()
				defer mu.Unlock()
				expected, _ := Assertion(revision, nil)
				matches := bytes.Equal(control.Bytes(), expected.Encode().Bytes())
				if !matches {
					return reply(server, id, ldap.ApplicationModifyResponse, 122, nil)
				}
				value = "after"
				revision = "43"
				return reply(server, id, ldap.ApplicationModifyResponse, 0, nil)
			}()
		}()
		l := ldap.NewConn(client, false)
		l.SetTimeout(time.Second)
		l.Start()
		return l, nil
	}
	cfg := Config{Server: "selected-dc", BaseDN: "DC=lab,DC=invalid"}
	client := NewWithFactory(cfg, factory)
	if e := client.Modify(context.Background(), "CN=x,DC=lab,DC=invalid", "group", "42", map[string]string{"description": "after"}); e != nil {
		t.Fatal(e)
	}
	if e := client.Modify(context.Background(), "CN=x,DC=lab,DC=invalid", "group", "42", map[string]string{"description": "stale"}); e == nil {
		t.Fatal("stale write accepted")
	}
	for i := 0; i < 2; i++ {
		if e := <-serverErrors; e != nil {
			t.Fatal(e)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if value != "after" || revision != "43" {
		t.Fatal("stale write changed directory state")
	}
}
