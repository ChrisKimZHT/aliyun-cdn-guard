package storage

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"aliyun-cdn-guard/internal/model"
)

// Keep a full 60-second, 241-QPS attack in the database before measuring.
func BenchmarkAttack(b *testing.B) {
	for _, batchSize := range []int{1, 256} {
		for _, active := range []bool{false, true} {
			b.Run(fmt.Sprintf("blocked=%t/batch=%d", active, batchSize), func(b *testing.B) {
				s, err := Open(filepath.Join(b.TempDir(), "guard.db"))
				if err != nil {
					b.Fatal(err)
				}
				defer s.Close()
				ctx := context.Background()
				err = s.withTx(ctx, func(tx *sql.Tx) error {
					for i := 0; i < 241*60; i++ {
						if _, err := tx.Exec("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)", "seed-"+strconv.Itoa(i), 1000-int64(i/241), "bench.example", "192.0.2.1", "", ""); err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
				if active {
					if _, err := s.db.Exec("INSERT INTO blocks VALUES (?, ?, ?, ?, ?, NULL)", "bench.example", "192.0.2.1", 1000, 2000, 1); err != nil {
						b.Fatal(err)
					}
				}
				opts := DetectionOptions{Threshold: 1000000000, WindowSeconds: 60, BaseDuration: 600, Multiplier: 2, MaxDuration: 86400, Now: 1000}
				b.ReportAllocs()
				b.ResetTimer()
				records := make([]Record, batchSize)
				for i := 0; i < b.N; {
					n := min(batchSize, b.N-i)
					for j := 0; j < n; j++ {
						records[j] = Record{Event: model.AccessEvent{EventID: strconv.Itoa(i + j), Timestamp: 1000, Domain: "bench.example", ClientIP: "192.0.2.1"}}
					}
					if _, err := s.RecordBatch(ctx, records[:n], opts); err != nil {
						b.Fatal(err)
					}
					i += n
				}
			})
		}
	}
}
