// Run public HTTP CRUD using explicit private endpoint and verified TLS trust.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	yamora "github.com/Andromeda1957/yamldb/yamora/drivers/go"
)

func run() error {
	host := flag.String("host", "127.0.0.1", "numeric private IPv4 endpoint")
	port := flag.Int("port", 0, "HTTPS port")
	ca := flag.String("ca", "", "trusted CA PEM file")
	cert := flag.String("cert", "", "optional client certificate PEM")
	key := flag.String("key", "", "optional client key PEM")
	read := flag.String("read-token-file", "", "private read-token file")
	write := flag.String("write-token-file", "", "private write-token file")
	collection := flag.String("collection", "packaged", "collection name")
	document := flag.String("document", "go-example", "new document name")
	flag.Parse()
	address, err := netip.ParseAddr(*host)
	if err != nil || *port < 1 || *port > 65535 {
		return errors.New("invalid endpoint")
	}
	trust, err := os.ReadFile(*ca)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trust) {
		return errors.New("invalid trust")
	}
	secure := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if (*cert == "") != (*key == "") {
		return errors.New("client certificate and key must be paired")
	}
	if *cert != "" {
		identity, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			return err
		}
		secure.Certificates = []tls.Certificate{identity}
	}
	readToken, err := os.ReadFile(*read)
	if err != nil {
		return err
	}
	writeToken, err := os.ReadFile(*write)
	if err != nil {
		return err
	}
	client, err := yamora.New(yamora.Config{
		Address: netip.AddrPortFrom(address, uint16(*port)), TLSConfig: secure,
		ReadToken: strings.TrimSpace(string(readToken)), WriteToken: strings.TrimSpace(string(writeToken)),
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source := []byte("# packaged client\r\nname: \"café\"\r\nvalue: 01\r\n")
	updatedSource := bytes.Replace(source, []byte("value: 01"), []byte("value: 02"), 1)
	stored, err := client.Put(ctx, *collection, *document, source, yamora.WriteOptions{CreateOnly: true})
	if err != nil {
		return err
	}
	found, err := client.Get(ctx, *collection, *document, "")
	if err != nil || !bytes.Equal(found.Source, source) {
		return errors.New("exact source check failed")
	}
	updated, err := client.Put(ctx, *collection, *document, updatedSource, yamora.WriteOptions{ETag: stored.ETag})
	if err != nil {
		return err
	}
	_, err = client.Put(ctx, *collection, *document, source, yamora.WriteOptions{ETag: stored.ETag})
	var rejected *yamora.HTTPError
	if !errors.As(err, &rejected) || rejected.Status != 412 {
		return errors.New("stale precondition was accepted")
	}
	found, err = client.Get(ctx, *collection, *document, "")
	if err != nil || !bytes.Equal(found.Source, updatedSource) {
		return errors.New("guarded update check failed")
	}
	if err = client.Delete(ctx, *collection, *document, updated.ETag); err != nil {
		return err
	}
	_, err = client.Get(ctx, *collection, *document, "")
	rejected = nil
	if !errors.As(err, &rejected) || rejected.Status != 404 {
		return errors.New("deleted document remains visible")
	}
	fmt.Println("YAMORA_GO_PACKAGE_CRUD_OK")
	return nil
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "packaged CRUD failed; preserve uncertain writes for explicit recovery")
		os.Exit(1)
	}
}
