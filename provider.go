// Package regfish implements a DNS record management client compatible
// with the libdns interfaces for regfish.
package regfish

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	rfns "github.com/regfish/regfish-dnsapi-go"
)

// Provider facilitates DNS record manipulation with regfish.
type Provider struct {
	APIToken string
	client   rfns.Client
	once     sync.Once
	mutex    sync.Mutex
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	records, err := p.client.GetRecordsByDomain(zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get records for zone %s: %w", zone, err)
	}

	var libdnsRecords []libdns.Record
	for _, rec := range records {
		record := p.convertToLibdnsRecord(rec, zone)
		if record != nil {
			libdnsRecords = append(libdnsRecords, record)
		}
	}

	return libdnsRecords, nil
}

// convertToLibdnsRecord converts a regfish record to a libdns record type
func (p *Provider) convertToLibdnsRecord(rec rfns.Record, zone string) libdns.Record {
	relName := libdns.RelativeName(rec.Name[:len(rec.Name)-1], zone)
	ttl := time.Duration(rec.TTL) * time.Second

	switch strings.ToUpper(rec.Type) {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(rec.Data)
		if err != nil {
			// Fallback to RR for invalid IP
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Data,
				TTL:  ttl,
			}
		}
		return libdns.Address{
			Name: relName,
			TTL:  ttl,
			IP:   ip,
		}
	case "MX":
		// Parse MX record data: "priority target"
		parts := strings.Fields(rec.Data)
		if len(parts) != 2 {
			// Fallback to RR for invalid MX data
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Data,
				TTL:  ttl,
			}
		}
		pref, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			// Fallback to RR for invalid preference
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Data,
				TTL:  ttl,
			}
		}
		return libdns.MX{
			Name:       relName,
			TTL:        ttl,
			Preference: uint16(pref),
			Target:     parts[1],
		}
	case "TXT":
		return libdns.TXT{
			Name: relName,
			TTL:  ttl,
			Text: rec.Data,
		}
	case "CNAME":
		return libdns.CNAME{
			Name:   relName,
			TTL:    ttl,
			Target: rec.Data,
		}
	case "NS":
		return libdns.NS{
			Name:   relName,
			TTL:    ttl,
			Target: rec.Data,
		}
	case "SRV":
		// Parse SRV record data: "priority weight port target"
		parts := strings.Fields(rec.Data)
		if len(parts) != 4 {
			// Fallback to RR for invalid SRV data
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Data,
				TTL:  ttl,
			}
		}
		priority, err1 := strconv.ParseUint(parts[0], 10, 16)
		weight, err2 := strconv.ParseUint(parts[1], 10, 16)
		port, err3 := strconv.ParseUint(parts[2], 10, 16)
		if err1 != nil || err2 != nil || err3 != nil {
			// Fallback to RR for invalid SRV data
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Data,
				TTL:  ttl,
			}
		}
		return libdns.SRV{
			Name:     relName,
			TTL:      ttl,
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   parts[3],
		}
	case "CAA":
		// Parse CAA record data: "flags tag value"
		parts := strings.SplitN(rec.Data, " ", 3)
		if len(parts) != 3 {
			// Fallback to RR for invalid CAA data
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Data,
				TTL:  ttl,
			}
		}
		flags, err := strconv.ParseUint(parts[0], 10, 8)
		if err != nil {
			// Fallback to RR for invalid flags
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Data,
				TTL:  ttl,
			}
		}
		return libdns.CAA{
			Name:  relName,
			TTL:   ttl,
			Flags: uint8(flags),
			Tag:   parts[1],
			Value: parts[2],
		}
	default:
		// Fallback to RR for unsupported record types
		return libdns.RR{
			Name: relName,
			Type: rec.Type,
			Data: rec.Data,
			TTL:  ttl,
		}
	}
}

// convertFromLibdnsRecord converts a libdns record to regfish record
func (p *Provider) convertFromLibdnsRecord(record libdns.Record, zone string) rfns.Record {
	rr := record.RR()
	
	rec := rfns.Record{
		Name: p.fqdn(rr.Name, zone),
		Type: rr.Type,
		Data: rr.Data,
		TTL:  int(rr.TTL.Seconds()),
	}

	// Handle specific record types with priority/preference
	switch typed := record.(type) {
	case libdns.MX:
		pref := int(typed.Preference)
		rec.Priority = &pref
	case libdns.SRV:
		pref := int(typed.Priority)
		rec.Priority = &pref
	}

	return rec
}
// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	var createdRecords []libdns.Record
	for _, record := range records {
		rec := p.convertFromLibdnsRecord(record, zone)

		createdRec, err := p.client.CreateRecord(rec)
		if err != nil {
			rr := record.RR()
			return nil, fmt.Errorf("failed to create record %s: %w", rr.Name, err)
		}

		createdRecord := p.convertToLibdnsRecord(createdRec, zone)
		if createdRecord != nil {
			createdRecords = append(createdRecords, createdRecord)
		}
	}

	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	var updatedRecords []libdns.Record

	for _, record := range records {
		// Attempt to update the record using the client
		updateRec, err := p.upsertRecord(record, zone)
		if err != nil {
			rr := record.RR()
			return nil, fmt.Errorf("failed to update record %s: %w", rr.Name, err)
		}

		// Convert updated rfns.Record to libdns.Record and append to the result slice
		updatedRecord := p.convertToLibdnsRecord(*updateRec, zone)
		if updatedRecord != nil {
			updatedRecords = append(updatedRecords, updatedRecord)
		}
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	all_records, err := p.client.GetRecordsByDomain(zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get records for zone %s: %w", zone, err)
	}

	var rrid int
	var deletedRecords []libdns.Record

	for _, record := range records {
		rr := record.RR()

		// Find the record ID
		rrid = 0
		for _, rec := range all_records {
			if p.fqdn(rec.Name, zone) == p.fqdn(rr.Name, zone) && rec.Type == rr.Type && rec.Data == rr.Data {
				rrid = rec.ID
				break
			}
		}

		if rrid == 0 {
			return nil, fmt.Errorf("record %s of type %s with data %s not found", rr.Name, rr.Type, rr.Data)
		}

		err := p.client.DeleteRecord(rrid)
		if err != nil {
			return nil, fmt.Errorf("failed to delete record ID %d: %w", rrid, err)
		}
		deletedRecords = append(deletedRecords, record)
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
