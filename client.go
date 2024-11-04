package regfish

import (
	"context"
	"fmt"
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

	update_rec := rfns.Record{
		Name:     p.fqdn(record.Name, zone),
		Type:     record.Type,
		Data:     record.Value,
		TTL:      int(record.TTL.Seconds()),
		Priority: &record.Priority,
	}

	for _, rec := range records {
		if fmt.Sprintf("%d", rec.ID) == record.ID || (p.fqdn(rec.Name, zone) == p.fqdn(record.Name, zone) && rec.Type == record.Type) {
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
