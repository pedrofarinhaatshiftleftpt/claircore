package microbatch

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"
)

// Insert creates batches limited by the configured batch size.
// Insert can be configured to return *sql.NullInt64 objects if
// the query defines this.
type Insert struct {
	// a transaction to send the batch on
	tx pgx.Tx
	// the current batch holding queued inserts.
	currBatch *pgx.Batch
	// the size we flush a batch
	batchSize int
	// the current queued inserts
	currQueue int
	// the total number of queued inserts
	total int
	// the timeout specified for a batch operation
	timeout time.Duration
	// whether we expect the Insert to return sql.NullInt64 IDs
	returning bool
	// a list of ids if returning option is used
	ids []*sql.NullInt64
}

// NewInsert returns a new micro batcher for inserting vulnerabilities to the database.
func NewInsert(tx pgx.Tx, batchSize int, timeout time.Duration, returning bool) *Insert {
	if timeout == 0 {
		timeout = time.Minute
	}
	return &Insert{
		tx:        tx,
		batchSize: batchSize,
		timeout:   timeout,
		returning: returning,
		ids:       []*sql.NullInt64{},
	}
}

// GetIDs returns any collected IDs from a returning sql statement
func (v *Insert) GetIDs() []*sql.NullInt64 {
	return v.ids
}

// Queue enqueues a query and its arguments into a batch.
//
// When Queue is called all queued inserts may be sent if the configured batch size is reached.
func (v *Insert) Queue(ctx context.Context, query string, args ...interface{}) error {
	// flush if batchSize reached
	if v.currQueue == v.batchSize {
		err := v.sendBatch(ctx)
		if err != nil {
			return fmt.Errorf("failed to flush batch when queueing vulnerability: %w", err)
		}
		v.currQueue = 0
	}

	v.currQueue++
	v.total++

	if v.currBatch == nil {
		v.currBatch = &pgx.Batch{}
	}

	v.currBatch.Queue(query, args...)
	return nil
}

// Done submits any existing queued inserts.
//
// Done MUST be called once the caller has queued all vulnerabilities to ensure the batches are properly
// flushed.
func (v *Insert) Done(ctx context.Context) error {
	if v.currQueue == 0 {
		return nil
	}

	// flush any remaining batches
	tctx, cancel := context.WithTimeout(ctx, v.timeout)
	res := v.tx.SendBatch(tctx, v.currBatch)
	defer res.Close()
	defer cancel()
	for i := 0; i < v.currQueue; i++ {
		if v.returning {
			var id sql.NullInt64
			err := res.QueryRow().Scan(&id)
			if err != nil {
				return fmt.Errorf("failed to query row: %d, %w", i, err)
			}
			v.ids = append(v.ids, &id)
		} else {
			_, err := res.Exec()
			if err != nil {
				return fmt.Errorf("failed in exec iteration %d, %w", i, err)
			}
		}
	}
	return nil
}

// sendBatch is called from v.Queue when the batchSize threshold is reached.
// Submits the current batch and calls res.Exec() over n = batchSize - 1 to find any errors.
func (v *Insert) sendBatch(ctx context.Context) error {
	tctx, cancel := context.WithTimeout(ctx, v.timeout)
	res := v.tx.SendBatch(tctx, v.currBatch)
	defer res.Close()
	defer cancel()
	// on exit set currBatch to nil, a new one will be created when fit
	defer func() {
		v.currBatch = nil
	}()
	for i := 0; i < v.batchSize; i++ {
		if v.returning {
			var id sql.NullInt64
			err := res.QueryRow().Scan(&id)
			if err != nil {
				return fmt.Errorf("failed to query row: %d, %w", i, err)
			}
			v.ids = append(v.ids, &id)
		} else {
			_, err := res.Exec()
			if err != nil {
				return fmt.Errorf("failed in exec iteration %d, %w", i, err)
			}
		}
	}
	return nil
}
