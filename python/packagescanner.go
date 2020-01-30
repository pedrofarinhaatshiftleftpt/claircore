// Package python contains components for interrogating python packages in
// container layers.
package python

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"io"
	"net/textproto"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Requirements file format:
// https://pip.pypa.io/en/stable/reference/pip_install/#requirements-file-format

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for files requirements.txt and extracts a subset of the the
// requirements file format.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "pip" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find requirements.txt files within the layer and enumerate the
// packages there.
//
// A return of (nil, nil) is expected if there's no file found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	log := zerolog.Ctx(ctx).With().
		Str("component", "python/Scanner.Scan").
		Str("version", ps.Version()).
		Str("layer", layer.Hash.String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
	})
	if !ok {
		return nil, errors.New("python: cannot seek on returned layer Reader")
	}

	ret := []*claircore.Package{}
	tr := tar.NewReader(rd)
	// Find possible rpm dbs
	// If none found, return
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		n, err := filepath.Rel("/", filepath.Join("/", h.Name))
		if err != nil {
			return nil, err
		}
		switch {
		case h.Typeflag != tar.TypeReg:
			// Should we chase symlinks with the correct name?
			continue
		case strings.HasSuffix(n, `.egg-info/PKG-INFO`):
			log.Debug().Str("file", n).Msg("found egg")
		case strings.HasSuffix(n, `.dist-info/METADATA`):
			log.Debug().Str("file", n).Msg("found wheel")
		default:
			continue
		}
		// These two files are in RFC8288 (email message) format, and the
		// keys we care about are shared.
		rd := textproto.NewReader(bufio.NewReader(tr))
		hdr, err := rd.ReadMIMEHeader()
		if err != nil {
			return nil, err
		}
		ret = append(ret, &claircore.Package{
			Name:      hdr.Get("Name"),
			Version:   hdr.Get("Version"),
			PackageDB: filepath.Join(n, "..", ".."),
			Kind:      "source",
			// TODO Is there some way to pick up on where a wheel or egg was
			// found?
			//RepositoryHint: "https://pypi.org/simple",
		})
	}
	if err != io.EOF {
		return nil, err
	}
	return ret, nil
}
