package vulnstore

import (
	"context"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// UpdateOperation is a unique update to the vulnstore by an Updater.
type UpdateOperation struct {
	ID          string
	Updater     string
	Fingerprint driver.Fingerprint
	Date        time.Time
}

// UpdateDiff represents added or removed vulnerabilities between update operations
type UpdateDiff struct {
	ID      string
	Added   []*claircore.Vulnerability
	Removed []*claircore.Vulnerability
}

// Updater is an interface exporting the necessary methods
// for updating a vulnerability database
type Updater interface {
	// GetHash should retrieve the latest value that the updater identified by a unique key
	// key will often be a claircore.Updater's unique name
	GetHash(ctx context.Context, key string) (string, error)
	// PutVulnerabilities
	PutVulnerabilities(ctx context.Context, updater string, UOID string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) error
	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided vulnerabilities, and computes a UpdateDiff for this UpdateOperation
	UpdateVulnerabilities(ctx context.Context, updater string, UOID string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) error
	// GetUpdateOperations returns a list of UpdateOperations in date descending order for the given updater
	GetUpdateOperations(ctx context.Context, updater string) ([]*UpdateOperation, error)
	// DeleteUpdateOperation removes an UpdateOperation and the associated vulnerabilities from the vulnstore
	DeleteUpdateOperation(ctx context.Context, UOID string) error
	// GetUpdateOperationDiff returns an UpdateDiff comprising the deleted or added vulnerabilites in the target update operation
	GetUpdateOperationDiff(ctx context.Context, UOID string) (UpdateDiff, error)
}
