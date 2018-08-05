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
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/chiefy/linodego"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	"strings"
)

// LinodeProvider is an implementation of a Provider for Linode's DNS.
type LinodeProvider struct {
	Client       linodego.Client
	domainFilter DomainFilter
	DryRun       bool
}

type LinodeChanges struct {
	Creates []*LinodeChangeCreate
	Deletes []*LinodeChangeDelete
	Updates []*LinodeChangeUpdate
}

type LinodeChangeCreate struct {
	Domain  *linodego.Domain
	Options linodego.DomainRecordCreateOptions
}

type LinodeChangeUpdate struct {
	Domain       *linodego.Domain
	DomainRecord *linodego.DomainRecord
	Options      linodego.DomainRecordUpdateOptions
}

type LinodeChangeDelete struct {
	Domain       *linodego.Domain
	DomainRecord *linodego.DomainRecord
}

// NewLinodeProvider initializes a new Linode DNS based Provider.
func NewLinodeProvider(domainFilter DomainFilter, dryRun bool) (*LinodeProvider, error) {
	token, ok := os.LookupEnv("LINODE_TOKEN")
	if !ok {
		return nil, fmt.Errorf("no token found")
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})

	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}

	linodeClient := linodego.NewClient(oauth2Client)

	provider := &LinodeProvider{
		Client:       linodeClient,
		domainFilter: domainFilter,
		DryRun:       dryRun,
	}
	return provider, nil
}

// Zones returns the list of hosted zones.
func (p *LinodeProvider) Zones() ([]*linodego.Domain, error) {
	zones, err := p.fetchZones()
	if err != nil {
		return nil, err
	}

	return zones, nil
}

// Records returns the list of records in a given zone.
func (p *LinodeProvider) Records() ([]*endpoint.Endpoint, error) {
	zones, err := p.Zones()
	if err != nil {
		return nil, err
	}

	var endpoints []*endpoint.Endpoint

	for _, zone := range zones {
		records, err := p.fetchRecords(zone.ID)
		if err != nil {
			return nil, err
		}

		for _, r := range records {
			if supportedRecordType(string(r.Type)) {
				name := fmt.Sprintf("%s.%s", r.Name, zone.Domain)

				// root name is identified by the empty string and should be
				// translated to zone name for the endpoint entry.
				if r.Name == "" {
					name = zone.Domain
				}

				endpoints = append(endpoints, endpoint.NewEndpointWithTTL(name, string(r.Type), endpoint.TTL(r.TTLSec), r.Target))
			}
		}
	}

	return endpoints, nil
}

func (p *LinodeProvider) fetchRecords(domainID int) ([]*linodego.DomainRecord, error) {
	records, err := p.Client.ListDomainRecords(context.TODO(), domainID, nil)
	if err != nil {
		return nil, err
	}

	return records, nil
}

func (p *LinodeProvider) fetchZones() ([]*linodego.Domain, error) {
	var zones []*linodego.Domain

	allZones, err := p.Client.ListDomains(context.TODO(), linodego.NewListOptions(0, ""))

	if err != nil {
		return nil, err
	}

	for _, zone := range allZones {
		if !p.domainFilter.Match(zone.Domain) {
			continue
		}

		zones = append(zones, zone)
	}

	return zones, nil
}

// submitChanges takes a zone and a collection of Changes and sends them as a single transaction.
func (p *LinodeProvider) submitChanges(changes LinodeChanges) error {
	for _, change := range changes.Creates {
		logFields := log.Fields{
			"record":   change.Options.Name,
			"type":     change.Options.Type,
			"action":   "Create",
			"zoneName": change.Domain.Domain,
			"zoneID":   change.Domain.ID,
		}

		log.WithFields(logFields).Info("Creating record.")

		if p.DryRun {
			log.WithFields(logFields).Info("Would create record.")
		} else {
			if _, err := p.Client.CreateDomainRecord(context.TODO(), change.Domain.ID, change.Options); err != nil {
				log.WithFields(logFields).Errorf(
					"Failed to Create record: %v",
					err,
				)
			}
		}
	}

	for _, change := range changes.Deletes {
		logFields := log.Fields{
			"record":   change.DomainRecord.Name,
			"type":     change.DomainRecord.Type,
			"action":   "Delete",
			"zoneName": change.Domain.Domain,
			"zoneID":   change.Domain.ID,
		}

		log.WithFields(logFields).Info("Deleting record.")

		if p.DryRun {
			log.WithFields(logFields).Info("Would delete record.")
		} else {
			if err := p.Client.DeleteDomainRecord(context.TODO(), change.Domain.ID, change.DomainRecord.ID); err != nil {
				log.WithFields(logFields).Errorf(
					"Failed to Delete record: %v",
					err,
				)
			}
		}
	}

	for _, change := range changes.Updates {
		logFields := log.Fields{
			"record":   change.Options.Name,
			"type":     change.Options.Type,
			"action":   "Update",
			"zoneName": change.Domain.Domain,
			"zoneID":   change.Domain.ID,
		}

		log.WithFields(logFields).Info("Updating record.")

		if p.DryRun {
			log.WithFields(logFields).Info("Would update record.")
		} else {
			if _, err := p.Client.UpdateDomainRecord(context.TODO(), change.Domain.ID, change.DomainRecord.ID, change.Options); err != nil {
				log.WithFields(logFields).Errorf(
					"Failed to Update record: %v",
					err,
				)
			}
		}
	}

	return nil
}

func getWeight() *int {
	weight := 1
	return &weight
}

func getPort() *int {
	port := 0
	return &port
}

func getPriority() *int {
	priority := 0
	return &priority
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *LinodeProvider) ApplyChanges(changes *plan.Changes) error {
	recordsByZoneId := make(map[string][]*linodego.DomainRecord)
	zones, err := p.fetchZones()
	zonesByID := make(map[string]*linodego.Domain)

	if err != nil {
		return err
	}

	zoneNameIDMapper := zoneIDName{}

	for _, z := range zones {
		zoneNameIDMapper.Add(strconv.Itoa(z.ID), z.Domain)
		zonesByID[strconv.Itoa(z.ID)] = z
	}

	// Fetch records for each zone
	for _, zone := range zones {
		records, err := p.fetchRecords(zone.ID)

		if err != nil {
			return err
		}

		recordsByZoneId[strconv.Itoa(zone.ID)] = append(recordsByZoneId[strconv.Itoa(zone.ID)], records...)
	}

	createsByZone := endpointsByZone(zones, changes.Create)
	updatesByZone := endpointsByZone(zones, changes.UpdateNew)
	deletesByZone := endpointsByZone(zones, changes.Delete)

	var linodeCreates []*LinodeChangeCreate
	var linodeUpdates []*LinodeChangeUpdate
	var linodeDeletes []*LinodeChangeDelete

	// Generate Creates
	for zoneID, creates := range createsByZone {
		zone := zonesByID[zoneID]

		if len(creates) == 0 {
			log.WithFields(log.Fields{
				"zoneID":   zoneID,
				"zoneName": zone.Domain,
			}).Debug("Skipping Zone, no creates found.")
			continue
		}

		records := recordsByZoneId[zoneID]

		for _, ep := range creates {
			matchedRecords := getRecordID(records, zone, ep)

			if len(matchedRecords) != 0 {
				log.WithFields(log.Fields{
					"zoneID":     zoneID,
					"zoneName":   zone.Domain,
					"dnsName":    ep.DNSName,
					"recordType": ep.RecordType,
				}).Warn("Records found which should not exist")
			}

			// TODO: if matchedRecords return more than 1 should we delete the duplicate?
			// or maybe there should be a de-dupe method somewhere?

			for _, target := range ep.Targets {
				recordType, err := convertRecordType(ep.RecordType)

				if err != nil {
					return err
				}

				linodeCreates = append(linodeCreates, &LinodeChangeCreate{
					Domain: zone,
					Options: linodego.DomainRecordCreateOptions{
						Target:   target,
						Name:     getStrippedRecordName(zone, ep),
						Type:     recordType,
						Weight:   getWeight(),
						Port:     getPort(),
						Priority: getPriority(),
						TTLSec:   int(ep.RecordTTL),
					},
				})
			}
		}
	}

	// Generate Updates
	for zoneID, updates := range updatesByZone {
		zone := zonesByID[zoneID]

		if len(updates) == 0 {
			log.WithFields(log.Fields{
				"zoneID":   zoneID,
				"zoneName": zone.Domain,
			}).Debug("Skipping Zone, no updates found.")
			continue
		}

		records := recordsByZoneId[zoneID]

		for _, ep := range updates {
			matchedRecords := getRecordID(records, zone, ep)

			if len(matchedRecords) == 0 {
				log.WithFields(log.Fields{
					"zoneID":     zoneID,
					"dnsName":    ep.DNSName,
					"zoneName":   zone.Domain,
					"recordType": ep.RecordType,
				}).Warn("Update Records not found.")
			}

			for _, target := range ep.Targets {
				recordType, err := convertRecordType(ep.RecordType)

				if err != nil {
					return err
				}

				for _, record := range matchedRecords {
					linodeUpdates = append(linodeUpdates, &LinodeChangeUpdate{
						Domain:       zone,
						DomainRecord: record,
						Options: linodego.DomainRecordUpdateOptions{
							Target:   target,
							Name:     getStrippedRecordName(zone, ep),
							Type:     recordType,
							Weight:   getWeight(),
							Port:     getPort(),
							Priority: getPriority(),
							TTLSec:   int(ep.RecordTTL),
						},
					})
				}
			}
		}
	}

	// Generate Deletes
	for zoneID, deletes := range deletesByZone {
		zone := zonesByID[zoneID]

		if len(deletes) == 0 {
			log.WithFields(log.Fields{
				"zoneID":   zoneID,
				"zoneName": zone.Domain,
			}).Debug("Skipping Zone, no deletes found.")
			continue
		}

		records := recordsByZoneId[zoneID]

		for _, ep := range deletes {
			matchedRecords := getRecordID(records, zone, ep)

			if len(matchedRecords) == 0 {
				log.WithFields(log.Fields{
					"zoneID":     zoneID,
					"dnsName":    ep.DNSName,
					"zoneName":   zone.Domain,
					"recordType": ep.RecordType,
				}).Warn("Records to Delete not found.")
			}

			if err != nil {
				return err
			}

			for _, record := range matchedRecords {
				linodeDeletes = append(linodeDeletes, &LinodeChangeDelete{
					Domain:       zone,
					DomainRecord: record,
				})
			}
		}
	}

	return p.submitChanges(LinodeChanges{
		Creates: linodeCreates,
		Deletes: linodeDeletes,
		Updates: linodeUpdates,
	})
}

func endpointsByZone(zones []*linodego.Domain, endpoints []*endpoint.Endpoint) map[string][]*endpoint.Endpoint {
	endpointsByZone := make(map[string][]*endpoint.Endpoint)
	zonesByID := make(map[string]*linodego.Domain)

	zoneNameIDMapper := zoneIDName{}

	for _, z := range zones {
		zoneNameIDMapper.Add(strconv.Itoa(z.ID), z.Domain)
		endpointsByZone[strconv.Itoa(z.ID)] = []*endpoint.Endpoint{}
		zonesByID[strconv.Itoa(z.ID)] = z
	}

	for _, ep := range endpoints {
		zoneID, _ := zoneNameIDMapper.FindZone(ep.DNSName)
		if zoneID == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected ", ep.DNSName)
			continue
		}
		endpointsByZone[zoneID] = append(endpointsByZone[zoneID], ep)
	}

	return endpointsByZone
}

func convertRecordType(recordType string) (linodego.DomainRecordType, error) {
	switch recordType {
	case "A":
		return linodego.RecordTypeA, nil
	case "AAAA":
		return linodego.RecordTypeAAAA, nil
	case "CNAME":
		return linodego.RecordTypeCNAME, nil
	case "TXT":
		return linodego.RecordTypeTXT, nil
	case "SRV":
		return linodego.RecordTypeSRV, nil
	default:
		return "", fmt.Errorf("invalid Record Type: %s", recordType)
	}
}

func getStrippedRecordName(zone *linodego.Domain, ep *endpoint.Endpoint) string {
	// Handle root
	if ep.DNSName == zone.Domain {
		return ""
	} else {
		return strings.TrimSuffix(ep.DNSName, "."+zone.Domain)
	}
}

func getRecordID(records []*linodego.DomainRecord, zone *linodego.Domain, ep *endpoint.Endpoint) []*linodego.DomainRecord {
	var matchedRecords []*linodego.DomainRecord

	for _, record := range records {
		if record.Name == getStrippedRecordName(zone, ep) && string(record.Type) == ep.RecordType {
			matchedRecords = append(matchedRecords, record)
		}
	}

	return matchedRecords
}
