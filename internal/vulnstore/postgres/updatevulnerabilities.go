package postgres

import (
	"context"
	"crypto/md5"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/microbatch"
)

const (
	insertUpdateOperation = `
	INSERT INTO update_operation (id, updater, fingerprint, date)
	VALUES ($1, $2, $3, current_timestamp);
	`
	insertUpdateOperationDiff = `
	INSERT INTO update_diff (ou_id, kind, vuln_id)
	VALUES ($1, $2, $3);
	`
	// insertVulnerability will either update an existing vulnerability with the latest UpdateOperation id and not return an ID on conflict
	// or insert a new vulnerability and return an ID if no conflict is encountered.
	// if this query returns an ID it indicates the vulnerability has been "added" when computing a diff
	insertVulnerability1 = `
	INSERT INTO vuln (
		ou_id,
		hash,
		name,
		description,
		links,
		severity,
		package_name,
		package_version,
		package_kind,
		dist_id,
		dist_name,
		dist_version,
		dist_verion_code_name,
		dist_version_id,
		dist_arch,
		dist_cpe,
		dist_pretty_name,
		repo_name,
		repo_key,
		repo_uri,
		fixed_in_version,
		active
	) VALUES (
	  $1,
	  $2,
	  $3,
	  $4,
	  $5,
	  $6,
	  $7,
	  $8,
	  $9,
	  $10,
	  $11,
	  $12,
	  $13,
	  $14,
	  $15,
	  $16,
	  $17,
	  $18,
	  $19,
	  $20,
	  $21,
	  true
	) ON CONFLICT (hash) DO UPDATE SET ou_id = EXCLUDED.ou_id
	RETURNING id; -- will only return if hash conflict did not occur
	`
)

// updateVulnerabilities creates a new UpdateOperation for this update call, inserts the provided vulnerabilities
// and computes a diff comprising the removed and added vulnerabilities for this UpdateOperation.
func updateVulnerabilites(ctx context.Context, pool *pgxpool.Pool, updater string, UOID string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction")
	}
	defer tx.Rollback(ctx)

	// create UpdateOperation
	_, err = pool.Exec(ctx, insertUpdateOperation, UOID, updater, string(fingerprint))
	if err != nil {
		return fmt.Errorf("failed to create UpdaterOperation")
	}

	// batch insert vulnerabilities and record added IDs
	skipCt := 0
	added := []sql.NullInt64{}
	mBatcher := microbatch.NewInsert(tx, 2000, time.Minute)
	for _, vuln := range vulns {
		if vuln.Package == nil || vuln.Package.Name == "" {
			skipCt++
			continue
		}
		if vuln.Dist == nil || vuln.Dist.Name == "" {
			skipCt++
			continue
		}
		if vuln.Repo == nil {
			vuln.Repo = &claircore.Repository{}
		}
		hash := md5Vuln(vuln)
		err := mBatcher.Queue(ctx,
			insertVulnerability1,
			UOID,
			hash,
			vuln.Name,
			vuln.Description,
			vuln.Links,
			vuln.Severity,
			vuln.Package.Name,
			vuln.Package.Version,
			vuln.Package.Kind,
			vuln.Dist.DID,
			vuln.Dist.Name,
			vuln.Dist.Version,
			vuln.Dist.VersionCodeName,
			vuln.Dist.VersionID,
			vuln.Dist.Arch,
			vuln.Dist.CPE,
			vuln.Dist.PrettyName,
			vuln.Repo.Name,
			vuln.Repo.Key,
			vuln.Repo.URI,
			vuln.FixedInVersion,
		)
		if err != nil {
			return fmt.Errorf("failed to queue vulnerability: %v", err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("failed to finish batch vulnerability insert: %v", err)
	}

	//
}

// hashVuln creates an md5 from the vulnerability data used for
// unique constraint checks.
//
// go optimizes string -> byte conversion in range loops
// see: http://devs.cloudimmunity.com/gotchas-and-common-mistakes-in-go-golang/index.html#string_byte_slice_conv
func md5Vuln(vuln *claircore.Vulnerability) string {
	b := []byte{}
	for _, v := range []byte(vuln.Name) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Description) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Links) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Severity) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Package.Name) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Package.Version) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Package.Kind) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.DID) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.Name) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.Version) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.VersionCodeName) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.VersionID) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.Arch) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.CPE) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Dist.PrettyName) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Repo.Name) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Repo.Key) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.Repo.URI) {
		b = append(b, v)
	}
	for _, v := range []byte(vuln.FixedInVersion) {
		b = append(b, v)
	}
	return fmt.Sprintf("%x", md5.Sum(b))
}
