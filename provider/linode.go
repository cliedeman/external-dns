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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/chiefy/linodego"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
)

const (
	// LinodeCreate is a ChangeAction enum value
	LinodeCreate = "CREATE"
	// LinodeDelete is a ChangeAction enum value
	LinodeDelete = "DELETE"
	// LinodeUpdate is a ChangeAction enum value
	LinodeUpdate = "UPDATE"
)

// LinodeProvider is an implementation of Provider for Linode's DNS.
type LinodeProvider struct {
	Client linodego.Client
	// only consider hosted zones managing domains ending in this suffix
	domainFilter DomainFilter
	DryRun       bool
}

// LinodeChange differentiates between ChangActions
type LinodeChange struct {
	Action       string
	Domain       linodego.Domain
	DomainRecord linodego.DomainRecord
}

// NewLinodeProvider initializes a new Linode DNS based Provider.
func NewLinodeProvider(domainFilter DomainFilter, dryRun bool) (*LinodeProvider, error) {
	token, ok := os.LookupEnv("LINODE_TOKEN")
	if !ok {
		return nil, fmt.Errorf("No token found")
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

	endpoints := []*endpoint.Endpoint{}

	for _, zone := range zones {
		records, err := p.fetchRecords(zone.ID)
		if err != nil {
			return nil, err
		}

		for _, r := range records {
			if supportedRecordType(string(r.Type)) {
				name := r.Name + "." + strconv.Itoa(zone.ID)

				// root name is identified by @ and should be
				// translated to zone name for the endpoint entry.
				if r.Name == "@" {
					name = strconv.Itoa(zone.ID)
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
	var listOpts *linodego.ListOptions

	// Fetch specific domains or fetch all
	if len(p.domainFilter.filters) > 0 {
		orConditions := []map[string]string{}

		for _, filter := range p.domainFilter.filters {
			orConditions = append(orConditions, map[string]string{
				"domain": filter,
			})
		}

		filterJSON, err := json.Marshal(map[string]interface{}{
			"+or": orConditions,
		})

		if err != nil {
			return nil, err
		}

		listOpts = linodego.NewListOptions(0, string(filterJSON))
	} else {
		listOpts = linodego.NewListOptions(0, "")
	}

	zones, err := p.Client.ListDomains(context.TODO(), listOpts)
	if err != nil {
		return nil, err
	}

	// TODO: remove
	for _, zone := range zones {
		log.WithFields(log.Fields{}).Debugf("Zone Retrieved: %+v", zone)
	}

	return zones, nil
}

// submitChanges takes a zone and a collection of Changes and sends them as a single transaction.
func (p *LinodeProvider) submitChanges(changes []*LinodeChange) error {
	// return early if there is nothing to change
	if len(changes) == 0 {
		return nil
	}

	zones, err := p.Zones()
	if err != nil {
		return err
	}

	// separate into per-domain change sets to be passed to the API.
	changesByZone := linodeChangesByZone(zones, changes)
	for zoneID, changes := range changesByZone {
		if len(changes) == 0 {
			log.WithFields(log.Fields{
				"zoneID": zoneID,
			}).Debug("Skipping Zone, no changes found.")
			continue
		}

		domainID, err := strconv.Atoi(zoneID)

		if err != nil {
			return err
		}

		records, err := p.fetchRecords(domainID)
		if err != nil {
			log.Errorf("Failed to list records in the zone: %s, Error: %v", zoneID, err)
			continue
		}
		for _, change := range changes {
			logFields := log.Fields{
				"record": change.DomainRecord.Name,
				"type":   change.DomainRecord.Type,
				"action": change.Action,
				"zoneID": zoneID,
			}

			log.WithFields(logFields).Info("Changing record.")

			if p.DryRun {
				continue
			}

			// TOOD dont think this is needed
			originalName := change.DomainRecord.Name
			change.DomainRecord.Name = strings.TrimSuffix(change.DomainRecord.Name, "."+change.Domain.Domain)
			log.WithFields(log.Fields{
				"name":        originalName,
				"trimmedName": change.DomainRecord.Name,
			}).Info("Trimming Name")

			switch change.Action {
			case LinodeCreate:
				_, err = p.Client.CreateDomainRecord(context.TODO(), domainID,
					linodego.DomainRecordCreateOptions{
						Target:   change.DomainRecord.Target,
						Name:     change.DomainRecord.Name,
						Type:     change.DomainRecord.Type,
						Weight:   getWeight(),
						Port:     getPort(),
						Priority: getPriority(),
					})
				if err != nil {
					return err
				}
			case LinodeDelete:
				recordID := p.getRecordID(records, change.DomainRecord)
				err = p.Client.DeleteDomainRecord(context.TODO(), domainID, recordID)
				if err != nil {
					return err
				}
			case LinodeUpdate:
				recordID := p.getRecordID(records, change.DomainRecord)
				_, err = p.Client.UpdateDomainRecord(context.TODO(), domainID, recordID,
					linodego.DomainRecordUpdateOptions{
						Target:   change.DomainRecord.Target,
						Name:     change.DomainRecord.Name,
						Type:     change.DomainRecord.Type,
						Weight:   getWeight(),
						Port:     getPort(),
						Priority: getPriority(),
					})
				if err != nil {
					return err
				}
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
	combinedChanges := make([]*LinodeChange, 0, len(changes.Create)+len(changes.UpdateNew)+len(changes.Delete))

	creates, err := newLinodeChanges(LinodeCreate, changes.Create)

	if err != nil {
		return err
	}

	combinedChanges = append(combinedChanges, creates...)

	updates, err := newLinodeChanges(LinodeUpdate, changes.UpdateNew)

	if err != nil {
		return err
	}

	combinedChanges = append(combinedChanges, updates...)

	deletes, err := newLinodeChanges(LinodeDelete, changes.Delete)

	if err != nil {
		return err
	}

	combinedChanges = append(combinedChanges, deletes...)

	return p.submitChanges(combinedChanges)
}

// newLinodeChanges returns a collection of Changes based on the given records and action.
func newLinodeChanges(action string, endpoints []*endpoint.Endpoint) ([]*LinodeChange, error) {
	changes := make([]*LinodeChange, 0, len(endpoints))

	for _, endpoint := range endpoints {
		change, err := newLinodeChange(action, endpoint)

		if err != nil {
			return nil, err
		}

		changes = append(changes, change...)
	}

	return changes, nil
}

func newLinodeChange(action string, endpoint *endpoint.Endpoint) ([]*LinodeChange, error) {
	changes := make([]*LinodeChange, 0, len(endpoint.Targets))

	recordType, err := convertRecordType(endpoint.RecordType)

	if err != nil {
		return nil, err
	}

	for _, target := range endpoint.Targets {
		change := &LinodeChange{
			Action: action,
			DomainRecord: linodego.DomainRecord{
				Name:   endpoint.DNSName,
				Type:   recordType,
				TTLSec: int(endpoint.RecordTTL),
				Target: target,
			},
		}

		changes = append(changes, change)
	}

	return changes, nil
}

func convertRecordType(recordType string) (linodego.DomainRecordType, error) {
	switch recordType {
	case "A":
		return linodego.RecordTypeA, nil
	case "AAAA":
		return linodego.RecordTypeAAAA, nil
	case "NS":
		return linodego.RecordTypeNS, nil
	case "MX":
		return linodego.RecordTypeMX, nil
	case "CNAME":
		return linodego.RecordTypeCNAME, nil
	case "TXT":
		return linodego.RecordTypeTXT, nil
	case "SRV":
		return linodego.RecordTypeSRV, nil
	case "PRT":
		return linodego.RecordTypePTR, nil
	case "CAA":
		return linodego.RecordTypeCAA, nil
	default:
		return "", fmt.Errorf("Invalid Record Type: %s", recordType)
	}
}

// getRecordID returns the ID from a record.
// the ID is mandatory to update and delete records
func (p *LinodeProvider) getRecordID(records []*linodego.DomainRecord, record linodego.DomainRecord) int {
	for _, zoneRecord := range records {
		if zoneRecord.Name == record.Name && zoneRecord.Type == record.Type {
			return zoneRecord.ID
		}
	}
	return 0
}

// linodechangesByDomain separates a multi-domain change into a single change per domain.
func linodeChangesByZone(zones []*linodego.Domain, changeSet []*LinodeChange) map[string][]*LinodeChange {
	changes := make(map[string][]*LinodeChange)
	zonesByID := make(map[string]*linodego.Domain)

	zoneNameIDMapper := zoneIDName{}
	for _, z := range zones {
		zoneNameIDMapper.Add(strconv.Itoa(z.ID), z.Domain)
		changes[strconv.Itoa(z.ID)] = []*LinodeChange{}
		zonesByID[strconv.Itoa(z.ID)] = z
	}

	for _, c := range changeSet {
		zoneID, _ := zoneNameIDMapper.FindZone(c.DomainRecord.Name)
		if zoneID == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected ", c.DomainRecord.Name)
			continue
		}
		changes[zoneID] = append(changes[zoneID], c)

		// TODO: there should be a better way
		c.Domain = *zonesByID[zoneID]
	}

	return changes
}
