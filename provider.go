// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for regfish.
package regfish

import (
	"context"
	"fmt"
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
		libdnsRecords = append(libdnsRecords, libdns.Record{
			ID:       fmt.Sprintf("%d", rec.ID),
			Type:     rec.Type,
			Name:     libdns.RelativeName(rec.Name[:len(rec.Name)-1], zone),
			Value:    rec.Data,
			TTL:      time.Duration(rec.TTL) * time.Second,
			Priority: getPriority(rec.Priority),
		})
	}

	return libdnsRecords, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	var createdRecords []libdns.Record
	for _, record := range records {

		rec := rfns.Record{
			Name:     p.fqdn(record.Name, zone),
			Type:     record.Type,
			Data:     record.Value,
			TTL:      int(record.TTL.Seconds()),
			Priority: &record.Priority,
		}

		createdRec, err := p.client.CreateRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("failed to create record %s: %w", record.Name, err)
		}

		createdRecords = append(createdRecords, libdns.Record{
			ID:       fmt.Sprintf("%d", createdRec.ID),
			Type:     createdRec.Type,
			Name:     libdns.RelativeName(createdRec.Name, zone),
			Value:    createdRec.Data,
			TTL:      time.Duration(createdRec.TTL) * time.Second,
			Priority: getPriority(createdRec.Priority),
		})
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
		// Map libdns.Record to rfns.Record

		// Attempt to update the record using the client
		updateRec, err := p.upsertRecord(record, zone)
		if err != nil {
			return nil, fmt.Errorf("failed to update record %s: %w", record.Name, err)
		}

		// Map updated rfns.Record to libdns.Record and append to the result slice
		updatedRecords = append(updatedRecords, libdns.Record{
			ID:       fmt.Sprintf("%d", updateRec.ID),
			Type:     updateRec.Type,
			Name:     libdns.RelativeName(updateRec.Name, zone),
			Value:    updateRec.Data,
			TTL:      time.Duration(updateRec.TTL) * time.Second,
			Priority: getPriority(updateRec.Priority),
		})
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

		// Find the record ID
		rrid = 0
		for _, rec := range all_records {
			if fmt.Sprintf("%d", rec.ID) == record.ID || (p.fqdn(rec.Name, zone) == p.fqdn(record.Name, zone) && rec.Type == record.Type && rec.Data == record.Value) {
				rrid = rec.ID
				break
			}
		}

		if rrid == 0 {
			return nil, fmt.Errorf("record %s of type %s with data %s not found", record.Name, record.Type, record.Value)
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
