package postgres

import (
	"context"
	"crypto/md5"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"
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
	selectNewestUpdateOperation = `
	SELECT (id) FROM updater_operation
	WHERE updater = $1 ORDER BY date LIMIT 1;
	`
	selectVulnerabilityIDByUOID = `
	SELECT (id) FROM vuln 
	WHERE uo_id = $1;
	`
	updateVulnerabilityActiveFalse = `
	UPDATE vuln SET active = false 
	WHERE id = $1;
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
	) ON CONFLICT (hash) DO UPDATE SET ou_id = EXCLUDED.ou_id, active = true
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

	// get previous UpdateOperation
	var prevUOID string
	err = tx.QueryRow(ctx, selectNewestUpdateOperation, updater).Scan(&prevUOID)
	switch err {
	case sql.ErrNoRows:
		prevUOID = ""
	default:
		return fmt.Errorf("failed to retrieve previous UpdateOperation ID")
	}

	// create UpdateOperation
	_, err = pool.Exec(ctx, insertUpdateOperation, UOID, updater, string(fingerprint))
	if err != nil {
		return fmt.Errorf("failed to create UpdaterOperation")
	}

	// batch insert vulnerabilities and record added IDs
	skipCt := 0
	mBatcher := microbatch.NewInsert(tx, 2000, time.Minute, true)
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

	// if no previous UOID exists we do not need to
	// create a diff. early return
	if prevUOID == "" {
		return nil
	}

	// gather removed and added and create diff
	// added ids were collected via microbatcher
	added := mBatcher.GetIDs()
	var removed []*sql.NullInt64
	// errors will be present during row access if exists
	rows, err := tx.Query(ctx, selectVulnerabilityIDByUOID, prevUOID)
	switch {
	case err == pgx.ErrNoRows:
		// check if error simply means no rows. hop out of switch if so
	case err != nil:
		// we have a legitimate error. return it
		return fmt.Errorf("failed to retrieve vulns with previous UOID: %w", err)
	default:
		// collect removed vuln ids from query
		for rows.Next() {
			var removedID sql.NullInt64
			err := rows.Scan(&removedID)
			if err != nil {
				return fmt.Errorf("failed to scan id of deleted record: %w", err)
			}
		}
	}

	// create added diffs
	for _, addID := range added {
		if addID.Valid {
			_, err := tx.Exec(ctx, insertUpdateOperationDiff, UOID, "add", addID)
			if err != nil {
				return fmt.Errorf("failed to create added dif: %w", err)
			}
		}
	}
	// create remove diff and set removed ids to active=false
	for _, removedID := range removed {
		if removedID.Valid {
			_, err := tx.Exec(ctx, insertUpdateOperationDiff, UOID, "delete", removedID)
			if err != nil {
				return fmt.Errorf("failed to create added dif: %w", err)
			}
			_, err = tx.Exec(ctx, updateVulnerabilityActiveFalse, removedID)
			if err != nil {
				return fmt.Errorf("failed to set record %d to active = false: %w", err)
			}
		}
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
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
