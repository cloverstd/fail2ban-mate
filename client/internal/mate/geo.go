package mate

import (
	"compress/gzip"
	"context"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type GeoDB struct{ db *maxminddb.Reader }

func OpenGeo(path string) (*GeoDB, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &GeoDB{db: db}, nil
}
func (g *GeoDB) Close() {
	if g != nil && g.db != nil {
		_ = g.db.Close()
	}
}
func (g *GeoDB) Lookup(ip string) Geo {
	if g == nil || g.db == nil {
		return Geo{}
	}
	var record struct {
		Country struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  *float64 `maxminddb:"latitude"`
			Longitude *float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	if err := g.db.Lookup(net.ParseIP(ip), &record); err != nil {
		return Geo{}
	}
	return Geo{Country: record.Country.Names["en"], City: record.City.Names["en"], Latitude: record.Location.Latitude, Longitude: record.Location.Longitude}
}
func UpdateGeo(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	var last error
	for month := 0; month < 2; month++ {
		now := time.Now().UTC()
		date := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -month, 0).Format("2006-01")
		url := "https://download.db-ip.com/free/dbip-city-lite-" + date + ".mmdb.gz"
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		if res.StatusCode != 200 {
			_ = res.Body.Close()
			last = fmt.Errorf("DB-IP download status %d", res.StatusCode)
			continue
		}
		err = installGeo(res.Body, path)
		_ = res.Body.Close()
		if err == nil {
			return nil
		}
		last = err
	}
	return fmt.Errorf("geolocation update failed (existing database preserved): %w", last)
}
func installGeo(body io.Reader, path string) error {
	gz, err := gzip.NewReader(body)
	if err != nil {
		return err
	}
	defer gz.Close()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".geo-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_ = tmp.Chmod(0600)
	n, copyErr := io.Copy(tmp, io.LimitReader(gz, 512*1024*1024+1))
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > 512*1024*1024 {
		return fmt.Errorf("database too large")
	}
	db, err := maxminddb.Open(name)
	if err != nil {
		return err
	}
	if err = db.Verify(); err != nil {
		_ = db.Close()
		return err
	}
	_ = db.Close()
	return os.Rename(name, path)
}
