package regfish

import (
	"context"
	"strings"

	"github.com/libdns/libdns"
	rfns "github.com/regfish/regfish-dnsapi-go"
)

// init initializes the provider.
func (p *Provider) init(ctx context.Context) {
	p.once.Do(func() {
		p.client = *rfns.NewClient(p.APIToken)
	})
}

// fqdn returns a fully qualified domain name.
func (p *Provider) fqdn(name, zone string) string {
	name = strings.TrimRight(name, ".")
	zone = strings.TrimRight(zone, ".")
	if !strings.HasSuffix(name, zone) {
		name += "." + zone
	}
	return name + "."
}

// upserRecords adds or updates records to the zone. It returns the records that were added or updated.
func (p *Provider) upsertRecord(record libdns.Record, zone string) (*rfns.Record, error) {

	records, err := p.client.GetRecordsByDomain(zone)
	if err != nil {
		return nil, err
	}

	rr := record.RR()

	update_rec := rfns.Record{
		Name: p.fqdn(rr.Name, zone),
		Type: rr.Type,
		Data: rr.Data,
		TTL:  int(rr.TTL.Seconds()),
		//Priority: &record.Priority,
	}

	switch rec := record.(type) {
	case libdns.SRV:
	case libdns.ServiceBinding:
		priority := int(rec.Priority)
		update_rec.Priority = &priority
	case libdns.MX:
		pref := int(rec.Preference)
		update_rec.Priority = &pref
	}

	for _, rec := range records {
		// libdns.Record no longer provides the ID field..
		// So we need to compare the FQDN and Type to find the record.
		// This will fail if there are multiple records with the same FQDN and Type.
		if p.fqdn(rec.Name, zone) == p.fqdn(rr.Name, zone) && rec.Type == rr.Type {
			updatedRecord, err := p.client.UpdateRecordById(rec.ID, update_rec)
			return &updatedRecord, err
		}
	}

	createdRecord, err := p.client.CreateRecord(update_rec)
	return &createdRecord, err
}

// getPriority returns the priority of a record and 0 if it is nil.
func getPriority(prio *int) int {
	if prio != nil {
		return *prio
	}
	return 0
}
