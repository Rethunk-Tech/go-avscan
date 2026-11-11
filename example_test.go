package avscan_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Totative/go-avscan"
)

func Example() {
	check := func(ctx context.Context, s avscan.Scanner, dir string) error {
		d, found, err := s.Scan(ctx, dir)
		switch {
		case errors.Is(err, avscan.ErrNoScanner):
			return nil
		case err != nil:
			return err
		case found:
			return fmt.Errorf("%s flagged %q: %s", d.Scanner, d.File, d.Name)
		}
		return nil
	}
	_ = check // e.g. check(ctx, avscan.Clamd{}, dir) or check(ctx, avscan.AMSI{AppName: "myapp"}, dir)
	fmt.Println(avscan.Command{Line: `clamdscan --no-summary "{path}"`}.Program())
	// Output: clamdscan
}

func ExampleClamd() {
	dir, err := os.MkdirTemp("", "avscan")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Outcome depends on whether a clamd daemon is reachable on this machine.
	d, found, err := avscan.Clamd{}.Scan(ctx, dir)
	_ = d
	_ = found
	_ = err
}

func ExampleCommand() {
	fmt.Println(avscan.Command{Line: `clamdscan --no-summary "{path}"`}.Program())
	// Output: clamdscan
}

func ExampleAMSI() {
	dir, err := os.MkdirTemp("", "avscan")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Outcome depends on whether this machine has an AMSI provider.
	d, found, err := avscan.AMSI{AppName: "example"}.Scan(ctx, dir)
	_ = d
	_ = found
	_ = err
}

func ExampleSecurityCenterProducts() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Product names depend on the antivirus Windows Security Center lists on this machine.
	_, _ = avscan.SecurityCenterProducts(ctx)
}
